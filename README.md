# TutoPay Web (Frontend + Node Backend)

This package contains:
- `public/`  -> the browser app (index.html, script.js, style.css, logo.png)
- `server.js` -> Node/Express API backend (serves the `public/` folder as well)

## Quick local test (optional)
1. Install Node.js 18+.
2. In this folder, run:
   - `npm install`
   - `npm start`
3. Open: http://localhost:4000

### API_BASE note
The frontend will use **same-origin** by default in production.
For local/dev, you can override:
`localStorage.setItem("TP_API_BASE","http://127.0.0.1:4000")`

## Upload / Deploy (cPanel option)
If your HoboHost account supports **Setup Node.js App**:

1. Upload this whole folder (or zip) to your account (e.g. `~/tutopay_app/`).
2. In cPanel: **Setup Node.js App**
   - Application root: the folder you uploaded (contains `server.js`, `package.json`)
   - Application startup file: `server.js`
   - Node version: 18+ (or whatever is available)
3. Click **Run NPM Install** (or run it inside Terminal if provided).
4. Start the app, then map it to `tutopay.online`.

Because the backend serves `/public`, your site should load directly.

## Static upload (only if you do NOT run Node)
If you are not running Node, you can only upload the frontend:
- Upload everything inside `public/` into `public_html/`

Note: In static-only mode, any features that call the backend API will not work.
