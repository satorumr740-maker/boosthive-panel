# BoostHive SMM Panel MVP

Flask-based SMM panel starter with:

- login and register
- customer dashboard
- manual wallet top-up for local testing
- multi-currency display
- order placement
- order history
- admin-only revenue section
- service management
- Render-ready PostgreSQL support
- Generic SMM provider API structure for `balance`, `services`, and `add` order actions

## Run locally

```powershell
cd "C:\Users\lenovo\OneDrive\Desktop\new bot\smm_panel_app"
pip install -r requirements.txt
python app.py
```

Open:

`http://127.0.0.1:5000`

## Demo logins

- customer: `demo` / `demo123`
- admin: `admin` / `admin123`

## Notes

- Wallet and service accounting are stored in `INR`.
- Display currencies are converted for UI only using placeholder rates in `app.py`.
- For local testing, use the `Quick Test Credit` button or keep `DATABASE_URL` unset so SQLite is used.
- On Render, set `BASE_URL`.
- To connect an SMM provider later, also set:
  - `SMM_API_URL`
  - `SMM_API_KEY`
- The included [render.yaml](</C:/Users/lenovo/OneDrive/Desktop/new bot/render.yaml>) provisions a free web service and free Postgres instance using Render Blueprint references.
- Real money collection is currently manual UPI + admin approval flow.

## Render deploy

1. Push the project to GitHub.
2. In Render, create a new Blueprint and point it to the repo.
3. During setup, fill:
   - `BASE_URL` with your Render app URL
   - `SMM_API_URL`
   - `SMM_API_KEY`
4. Deploy. Render will inject the Postgres `connectionString` as `DATABASE_URL`.

## Domain

- With current `render.yaml` service name (`boosthive-panel`), your default URL will typically be:
  - `https://boosthive-panel.onrender.com`
- If that name is unavailable, Render may assign a variant.
- You can attach your own custom domain later from Render dashboard.

## Manual Payment Flow

1. Set your UPI/QR on admin payments page.
2. User pays via UPI/QR and submits reference.
3. Admin approves request.
4. Wallet is credited only after approval.

Provider note:

- The provided SMM endpoint returned `403 Cloudflare` from this local environment when tested with `balance` and `services`.
- That usually means bot protection, IP filtering, or challenge mode.
- The integration code is ready, but the real proof test should be done from the deployed Render app using your actual env vars.
- Because the key was pasted into chat, rotate it after setup for safety.

## Production follow-up

- Replace placeholder exchange rates with a real FX source.
- Add migrations before making larger schema changes.
- If your SMM provider uses the common `key + action` API style, the admin panel can sync services and forward orders after setting env vars.
