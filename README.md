# AuthGuard AI

The workspace contains the React frontend and FastAPI backend in separate
folders. Run both during local development:

1. In `AuthGuard-main/authguard-backend`, install `requirements.txt` and start
   the API with `python -m uvicorn main:app --reload`.
2. In `AuthGuard-ai-main`, install the npm dependencies and run `npm run dev`.
3. Open `http://localhost:3000`. Vite proxies `/api` requests to the backend at
   `http://127.0.0.1:8000` by default.

Set `AUTHGUARD_API_URL` to change the Vite proxy target. Set
`VITE_API_BASE_URL` to a backend origin when the frontend is hosted separately.
