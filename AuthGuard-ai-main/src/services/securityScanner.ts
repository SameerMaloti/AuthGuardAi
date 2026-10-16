import {
  FindingSeverity,
  RiskLevel,
  ScanExecutionMode,
  ScenarioId,
  SecurityFinding,
  SecurityScanResult,
  UrlValidationResult,
  ExtensionSettings,
  WhitelistEntry,
} from '../types/security';
import { SCENARIOS } from '../data/mockScenarios';
import { analyzeWebsiteRisk, type BackendReputation } from './backendApi';

/**
 * Normalizes and validates user-submitted web addresses.
 * Prevents dangerous protocols (javascript:, data:, file:, etc.)
 * and formats hostname for security analysis.
 */
export function validateAndNormalizeUrl(rawInput: string): UrlValidationResult {
  const trimmed = (rawInput || '').trim();

  if (!trimmed) {
    return {
      isValid: false,
      error: 'Please enter a website address (for example: stripe-demo.com or yourbank.com)',
    };
  }

  // Check for dangerous pseudoprotocols
  const lower = trimmed.toLowerCase();
  if (
    lower.startsWith('javascript:') ||
    lower.startsWith('data:') ||
    lower.startsWith('file:') ||
    lower.startsWith('vbscript:') ||
    lower.startsWith('blob:')
  ) {
    return {
      isValid: false,
      error: 'Unsupported or unsafe protocol entered. Only web addresses (HTTP/HTTPS) are evaluated.',
    };
  }

  // Ensure scheme exists for URL parser
  let normalizedInput = trimmed;
  let assumedHttps = true;

  if (!/^https?:\/\//i.test(normalizedInput)) {
    normalizedInput = `https://${normalizedInput}`;
  } else {
    assumedHttps = normalizedInput.toLowerCase().startsWith('https://');
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedInput);
  } catch {
    return {
      isValid: false,
      error: 'Invalid website address format. Please enter a valid URL (e.g. checkout.stripe-demo.com).',
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Validate hostname structure
  if (!hostname) {
    return {
      isValid: false,
      error: 'Hostname is missing. Please enter a complete domain address.',
    };
  }

  // Check if it's localhost or an IP address or a standard domain with a TLD
  const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const hasValidTld = hostname.includes('.') && hostname.split('.').pop()!.length >= 2;

  if (!isLocalhost && !isIp && !hasValidTld) {
    return {
      isValid: false,
      error: 'Please include a valid domain extension (such as .com, .org, .net, or .io).',
    };
  }

  // Check for invalid characters in hostname
  if (/[^a-z0-9.-]/i.test(hostname)) {
    return {
      isValid: false,
      error: 'Domain contains invalid characters. Only letters, numbers, hyphens, and dots are permitted.',
    };
  }

  return {
    isValid: true,
    normalizedUrl: parsed.href,
    domain: hostname,
    isHttps: parsed.protocol === 'https:',
    protocol: parsed.protocol.replace(':', '').toUpperCase(),
    pathname: parsed.pathname,
  };
}

/**
 * Calculates Levenshtein edit distance between two strings
 * to detect brand typosquatting (e.g. "paypa1" vs "paypal").
 */
export function getLevenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Client-side URL and hostname heuristic analyzer, followed by backend
 * rule-based scoring. It does not fetch or inspect the target website.
 */
export async function executeSecurityScan(
  rawUrl: string,
  settings?: ExtensionSettings,
  whitelist?: WhitelistEntry[]
): Promise<SecurityScanResult> {
  // 1. Validate and normalize
  const validation = validateAndNormalizeUrl(rawUrl);
  if (!validation.isValid || !validation.domain || !validation.normalizedUrl) {
    throw new Error(validation.error || 'Invalid website URL');
  }

  const { domain, normalizedUrl, isHttps } = validation;
  const lowerDomain = domain.toLowerCase();

  // 2. Check if domain is in user's Safe List whitelist
  const isWhitelisted = whitelist?.some(
    (w) => w.domainPattern.toLowerCase() === lowerDomain
  );

  // 3. Collect structured security findings
  const findings: SecurityFinding[] = [];
  const safeChecks: string[] = [];

  let score = 94; // Baseline score
  let riskLevel: RiskLevel = 'LOW';
  let matchedScenarioId: ScenarioId = 'low';

  // Finding category 1: Transport & Protocol
  if (isHttps) {
    safeChecks.push('URL uses HTTPS scheme; the target certificate was not checked');
  } else {
    findings.push({
      id: 'f-proto-unencrypted',
      severity: 'CRITICAL',
      category: 'PROTOCOL',
      title: 'Unencrypted Connection (Insecure HTTP)',
      description: 'The submitted URL uses HTTP. If opened, the connection would not use TLS, so credentials could be exposed in transit.',
      remediation: 'Do not enter passwords or sensitive personal data on unencrypted HTTP pages. Look for https:// in the address bar.',
      technicalDetail: 'HTTP scheme present in the submitted URL; no network connection was made.',
    });
    score -= 35;
  }

  // Finding category 2: Domain Brand Lookalike / Typosquatting
  const highValueBrands = [
    { name: 'Apple', target: 'apple.com', keywords: ['apple', 'icloud', 'appleid', 'itunes'] },
    { name: 'Stripe', target: 'stripe.com', keywords: ['stripe', 'checkout-stripe'] },
    { name: 'PayPal', target: 'paypal.com', keywords: ['paypal', 'paypa1', 'pay-pal'] },
    { name: 'Google', target: 'google.com', keywords: ['google', 'gmail', 'accounts-google'] },
    { name: 'Microsoft', target: 'microsoft.com', keywords: ['microsoft', 'office365', 'outlook-login'] },
    { name: 'Chase Bank', target: 'chase.com', keywords: ['chase', 'chase-online', 'chasebank'] },
    { name: 'MetaMask', target: 'metamask.io', keywords: ['metamask', 'wallet-connect-fix'] },
  ];

  let brandImpersonated = false;
  for (const brand of highValueBrands) {
    const isExactBrandDomain = lowerDomain === brand.target || lowerDomain.endsWith(`.${brand.target}`);
    const containsKeyword = brand.keywords.some((kw) => lowerDomain.includes(kw));

    if (containsKeyword && !isExactBrandDomain) {
      brandImpersonated = true;
      findings.push({
        id: `f-brand-${brand.name.toLowerCase()}`,
        severity: 'CRITICAL',
        category: 'DOMAIN_HEURISTICS',
        title: `Deceptive Brand Lookalike (${brand.name} Impersonation)`,
        description: `This website includes "${brand.name}" in its domain name but does not belong to ${brand.target}. Attackers frequently create lookalike domains to trick victims into entering account credentials.`,
        remediation: `Never enter your ${brand.name} account credentials on this site. Navigate directly to ${brand.target} by typing it into your browser.`,
        technicalDetail: `Target host "${lowerDomain}" mismatches verified canonical authority "${brand.target}". High homoglyph/typosquat risk.`,
      });
      score -= 45;
      break;
    }
  }

  // Finding category 3: High-Risk TLD & Suspicious Domain Extensions
  const suspiciousTlds = ['.cc', '.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.buzz', '.click', '.monster', '.su'];
  const hasSuspiciousTld = suspiciousTlds.some((tld) => lowerDomain.endsWith(tld));
  if (hasSuspiciousTld) {
    findings.push({
      id: 'f-tld-suspicious',
      severity: 'HIGH',
      category: 'REPUTATION',
      title: 'High-Risk Top-Level Domain Extension',
      description: `The website uses a domain extension frequently associated with disposable phishing campaigns and automated spam generation.`,
      remediation: 'Verify the identity of the organization hosting this site before downloading attachments or submitting login forms.',
      technicalDetail: `TLD registered under high-abuse classification list.`,
    });
    score -= 20;
  } else {
    safeChecks.push('No local high-risk TLD match; registrar and reputation were not checked');
  }

  // Finding category 4: Suspicious Keywords in Domain
  const suspiciousKeywords = [
    { kw: 'verify', label: 'Urgent verification lure' },
    { kw: 'login-sync', label: 'Deceptive login synchronization lure' },
    { kw: 'invoice-portal', label: 'Unverified billing gateway lure' },
    { kw: 'wallet-drain', label: 'Cryptocurrency credential collector' },
    { kw: 'harvest', label: 'Automated credential harvester' },
    { kw: 'sec-update', label: 'Fake security update notice' },
  ];

  for (const item of suspiciousKeywords) {
    if (lowerDomain.includes(item.kw)) {
      findings.push({
        id: `f-kw-${item.kw}`,
        severity: 'HIGH',
        category: 'DOMAIN_HEURISTICS',
        title: `Deceptive Keyword Pattern ("${item.kw}")`,
        description: `Domain contains phishing keywords (${item.label}) typically used to induce artificial urgency during credential harvesting.`,
        remediation: 'Do not follow password reset or account verification prompts from this URL.',
        technicalDetail: `Keyword match against active threat-intelligence signature "${item.kw}".`,
      });
      score -= 25;
      break;
    }
  }

  // Finding category 5: Punycode / Homoglyph check
  if (lowerDomain.includes('xn--')) {
    findings.push({
      id: 'f-punycode-homoglyph',
      severity: 'HIGH',
      category: 'DOMAIN_HEURISTICS',
      title: 'Punycode Internationalized Domain Detected',
      description: 'Domain uses Punycode encoding (xn-- prefix), which may conceal Cyrillic or Greek lookalike characters designed to visually deceive human visitors.',
      remediation: 'Inspect the decoded ASCII representation in the browser address bar before interacting.',
      technicalDetail: 'The hostname contains an IDNA Punycode (xn--) label.',
    });
    score -= 25;
  } else {
    safeChecks.push('Homoglyph Check: Standard Latin ASCII characters with no hidden unicode substitutions');
  }

  // Adjust score for whitelist override
  if (isWhitelisted) {
    score = Math.max(score, 88);
    safeChecks.push('Safe List Override: Domain is marked as trusted in your local AuthGuard settings');
  }

  // Sensitivity calibration
  if (settings?.sensitivityPreset === 'strict') {
    score = Math.max(2, score - 6);
  } else if (settings?.sensitivityPreset === 'relaxed') {
    score = Math.min(100, score + 4);
  }

  // Final score clamping and risk classification
  score = Math.max(2, Math.min(100, score));

  if (score < 35 || brandImpersonated) {
    riskLevel = 'HIGH';
    matchedScenarioId = 'high';
  } else if (score < 70 || hasSuspiciousTld || findings.length > 0) {
    riskLevel = 'MEDIUM';
    matchedScenarioId = 'medium';
  } else {
    riskLevel = 'LOW';
    if (lowerDomain.includes('stripe') || lowerDomain.includes('checkout')) {
      matchedScenarioId = 'low';
    } else if (lowerDomain.includes('cloud') || lowerDomain.includes('vault')) {
      matchedScenarioId = 'cloudvault';
    } else {
      matchedScenarioId = 'github';
    }
  }

  // Send only the hostname and heuristic metadata to the backend. The frontend
  // does not fetch the target page, so page fields and redirect count are not
  // claimed as inspected signals.
  const backendReputation: BackendReputation = brandImpersonated
    ? 'malicious'
    : findings.length > 0
      ? 'suspicious'
      : 'unknown';
  const backendAssessment = await analyzeWebsiteRisk({
    hostname: domain,
    otp_field_detected: false,
    redirect_count: 0,
    reputation: backendReputation,
  });

  const backendRiskLevel: RiskLevel =
    backendAssessment.risk_level === 'high'
      ? 'HIGH'
      : backendAssessment.risk_level === 'medium'
        ? 'MEDIUM'
        : 'LOW';
  const riskRank: Record<RiskLevel, number> = { LOW: 0, MEDIUM: 1, HIGH: 2 };
  if (riskRank[backendRiskLevel] > riskRank[riskLevel]) {
    riskLevel = backendRiskLevel;
  }
  score = Math.min(score, 100 - backendAssessment.risk_score);

  if (riskLevel === 'HIGH') {
    matchedScenarioId = 'high';
  } else if (riskLevel === 'MEDIUM') {
    matchedScenarioId = 'medium';
  }

  if (safeChecks.length === 0 && riskLevel !== 'HIGH') {
    safeChecks.push('Origin Integrity: Passed baseline syntax and hostname checks');
  }

  // Pick matched scenario from dataset for complete forensic backing
  const matchedScenario = SCENARIOS[matchedScenarioId] || SCENARIOS.low;

  // Build summary explanations and remediation
  let summaryExplanation = '';
  let recommendedRemediation = '';

  if (riskLevel === 'HIGH') {
    summaryExplanation = `High risk hostname patterns detected for ${domain}. The submitted URL matches local brand or domain heuristics.`;
    recommendedRemediation = 'Do NOT enter passwords, phone numbers, or credit card details. Leave this website immediately and reset your password on the genuine site if already entered.';
  } else if (riskLevel === 'MEDIUM') {
    summaryExplanation = `Caution advised for ${domain}. Local URL heuristics or the backend rule assessment reported risk indicators.`;
    recommendedRemediation = 'Double-check the web address and sender identity before typing sensitive passwords or completing financial transactions.';
  } else {
    summaryExplanation = `No configured risk indicators were reported for ${domain}. This rule-based result does not verify the live website.`;
    recommendedRemediation = 'Continue cautiously. Open the organization’s official website directly before entering sensitive information.';
  }

  return {
    domain,
    fullUrl: normalizedUrl,
    normalizedUrl,
    riskLevel,
    score,
    isHttps: Boolean(isHttps),
    protocol: isHttps ? 'HTTPS scheme (certificate not checked)' : 'HTTP scheme',
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    executionMode: 'CLIENT_HEURISTIC' as ScanExecutionMode,
    findings,
    safeChecks,
    summaryExplanation,
    recommendedRemediation,
    matchedScenarioId,
    scenario: matchedScenario,
    auditHonesty: {
      clientHeuristicExecuted: true,
      remoteServerDeepInspectionSimulated: false,
      notice: 'The browser checked URL and hostname patterns, then sent the hostname and derived reputation to the AuthGuard backend for rule-based scoring. It did not inspect the live page, TLS certificate, redirects, forms, scripts, or reputation feeds.',
    },
    backendAssessment: {
      eventId: backendAssessment.event_id,
      riskScore: backendAssessment.risk_score,
      riskLevel: backendAssessment.risk_level,
      decision: backendAssessment.decision,
      reasons: backendAssessment.reasons,
      recommendedAction: backendAssessment.recommended_action,
      analysisMode: backendAssessment.analysis_mode,
    },
    technicalDetails: {
      ipAddress: 'Not resolved',
      issuingAuthority: 'Not checked',
      validityWindow: 'Not checked',
      cipherSuite: 'Not checked',
      monitoredFormFields: 0,
      networkEndpointsCount: 0,
      originScope: domain,
    },
  };
}
