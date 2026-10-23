# ArchNet Node — Railway Deployment

This guide explains how to deploy `archnet-node` on [Railway](https://railway.app).

## Deployment

1. Fork or push this repository to GitHub.
2. In Railway, click **New Project** > **Deploy from GitHub repo**.
3. Railway automatically detects `railway.toml` and `Dockerfile` at the repository root.
4. Add the following environment variables in your Railway service settings:
   - `API_HOST`: Your ArchNet panel URL (e.g. `https://panel.archnets.com`)
   - `SERVER_ID`: Server ID assigned in the panel
   - `SECRET_KEY`: Node secret key
5. Under service **Settings** > **Networking**, generate a public Railway domain (e.g. `your-node.up.railway.app`).
6. In your ArchNet panel, configure the node inbound:
   - Transport: `ws`
   - Port: `443`
   - Security: `tls`
   - Address: `your-node.up.railway.app`
