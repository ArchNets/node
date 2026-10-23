# Deploying ArchNet Node on KataBump

This directory contains the deployment package and orchestration launcher for hosting **ArchNet Node** on [KataBump](https://katabump.com) (or any other [Pterodactyl](https://pterodactyl.io)-based container hosting provider).

---

## How It Works

KataBump does not provide access to the host Docker daemon or `docker run` commands; it runs user applications inside isolated, unprivileged Pterodactyl containers using **Python** or **Node.js** runtime eggs.

Because `archnet-node` is compiled as a self-contained, statically linked Go binary (`CGO_ENABLED=0`), it can run directly inside KataBump's Python container without needing Docker or root privileges.

The provided Python launcher (`main.py` / `app.py`):
1. Loads credentials from `.env` or KataBump environment variables.
2. Automatically detects the allocated port (`SERVER_PORT` / `PORT`).
3. Auto-downloads and verifies required routing geodata (`geoip.dat`, `geosite.dat`).
4. Generates `config.yml` at `/home/container/config.yml`.
5. Spawns `./node server` and streams logs in real-time to the KataBump web console.
6. *(Optional)* Spawns a Cloudflare Tunnel (`cloudflared`) to expose the node over port **443 with HTTPS/WSS and full TLS** on your own domain!

---

## Protocol Compatibility on KataBump

| Protocol | Transport | Supported? | Notes |
| :--- | :--- | :---: | :--- |
| **VLESS** | WebSocket / gRPC / TCP / XHTTP | **Yes** | Recommended. Set `security: none` for direct port or `tls` with Cloudflare Tunnel. |
| **VMess** | WebSocket / gRPC / TCP | **Yes** | Standard user-space proxying. |
| **Trojan** | WebSocket / gRPC / TCP | **Yes** | Standard user-space proxying. |
| **Shadowsocks** | TCP / UDP | **Yes** | Uses allocated KataBump port. |
| **WireGuard / IPsec / OpenVPN** | Kernel TUN | **No** | Containers lack `CAP_NET_ADMIN` / `/dev/net/tun`. |

---

## Step-by-Step Deployment Guide

### Step 1: Create a Server on KataBump
1. Go to [katabump.com](https://katabump.com) and log in.
2. Click **Create a Server**.
3. Select **Python** as the runtime.
4. Set a name for your server and click **Create**.
5. Note the allocated IP/Hostname and Port in the server settings (e.g., `fr-node-12.katabump.fr:25565`).

### Step 2: Build the Deployment ZIP Package
On your local machine, run the packaging script from the repository root:

```bash
chmod +x deploy/katabump/package.sh
./deploy/katabump/package.sh
```

This will produce `deploy/katabump/archnet-node-katabump.zip` containing:
- The compiled Linux AMD64 `node` binary
- Geo-routing data (`geoip.dat`, `geosite.dat`)
- Python launcher (`main.py`, `app.py`)
- Environment and configuration templates

### Step 3: Upload and Extract on KataBump
1. Open your server on [control.katabump.com](https://control.katabump.com).
2. Go to the **Files** tab.
3. Drag and drop `archnet-node-katabump.zip` into the file manager.
4. Click the three dots next to the uploaded ZIP file and click **Unarchive** (Extract).
5. All files should now be at the root of `/home/container`.

### Step 4: Configure Credentials (.env)
In the **Files** tab, edit the `.env` file (or rename `.env.example` to `.env`):

```ini
# ArchNet Panel Details
API_HOST=https://panel.yourdomain.com
SERVER_ID=26
SECRET_KEY=your-secret-key-here
LOG_LEVEL=info

# (Optional) For Cloudflare Tunnel on port 443 with TLS:
# CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoi...
```

Save the file.

### Step 5: Configure the Node in Your ArchNet Panel

#### Option A: Direct Port (No SSL / Raw High Port)
In your ArchNet Admin Panel, configure the node inbound:
- **Type**: `vless` (or `vmess`, `trojan`)
- **Transport**: `ws` (WebSocket)
- **Port**: Set to the exact port assigned by KataBump (e.g. `25565`)
- **Security**: `none`
- **WS Path**: `/` or `/archnets`

#### Option B: Cloudflare Tunnel (Full HTTPS / TLS on Port 443)
If you want users to connect to `node.yourdomain.com:443` with valid SSL:
1. Go to **Cloudflare Zero Trust** > **Networks** > **Tunnels**.
2. Create a new tunnel, name it (e.g. `katabump-node`), and copy the tunnel token.
3. Add a Public Hostname in Cloudflare Tunnel:
   - **Subdomain**: `node`
   - **Domain**: `yourdomain.com`
   - **Service Type**: `HTTP`
   - **URL**: `localhost:8080` (or your panel inbound port)
4. Add `CLOUDFLARE_TUNNEL_TOKEN=<token>` to your `.env` file on KataBump.
5. In your ArchNet panel, configure the node inbound to port `8080`, but set the client connection address to `node.yourdomain.com:443` with `security: tls`.

### Step 6: Start the Server
1. Go to the **Console** tab on `control.katabump.com`.
2. Click **Start**.
3. Watch the logs. You should see:
   - System checks and architecture verification
   - ArchNet Node starting up
   - Connection established to your ArchNet Panel

---

## Important KataBump Platform Notes

1. **Free Plan Renewal**:
   - Free servers on KataBump expire every **4 days**.
   - You must renew the server manually in `dashboard.katabump.com` within 48 hours before expiration.
   - If expired, the server will be suspended and deleted permanently after 24 hours. Paid plans (€1.50/mo+) do not have this requirement.
2. **Resource Limits**:
   - Free plan has **308 MB RAM** and **25% CPU**.
   - `archnet-node` consumes ~60–80 MB RAM, running comfortably inside the free tier limit.
3. **Single Port Constraint**:
   - Each KataBump server has only one external port mapped. Do not attempt to run multiple inbounds on different ports unless using Cloudflare Tunnel.
