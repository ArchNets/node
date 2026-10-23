#!/usr/bin/env bash
# ==============================================================================
# ArchNet Node — KataBump Package Generator
# ==============================================================================
# Compiles archnet-node for Linux AMD64, downloads geodata files, and builds a
# clean ZIP archive ready for 1-click deployment on KataBump (or any Pterodactyl host).
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/dist"
ZIP_NAME="archnet-node-katabump.zip"
ZIP_PATH="${SCRIPT_DIR}/${ZIP_NAME}"

echo "=========================================================="
echo " Building ArchNet Node KataBump Deployment Package"
echo "=========================================================="
echo "Repository root: ${REPO_ROOT}"
echo "Output package:  ${ZIP_PATH}"
echo "----------------------------------------------------------"

# 1. Clean previous build artifacts
rm -rf "${OUTPUT_DIR}" "${ZIP_PATH}"
mkdir -p "${OUTPUT_DIR}"

# 2. Compile Go binary for Linux AMD64
echo "[1/4] Compiling archnet-node (Linux AMD64, static)..."
cd "${REPO_ROOT}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOEXPERIMENT=jsonv2 \
    go build -trimpath \
    -ldflags "-X 'github.com/archnets/node/cmd.version=katabump-$(date +%Y%m%d)' -s -w -buildid= -checklinkname=0" \
    -o "${OUTPUT_DIR}/node" .
chmod +x "${OUTPUT_DIR}/node"
echo "      Binary built successfully ($(du -h "${OUTPUT_DIR}/node" | cut -f1))"

# 3. Download Geo-data files
echo "[2/4] Ensuring geoip.dat and geosite.dat..."
GEOIP_URL="https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat"
GEOSITE_URL="https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat"

if [[ -f "/tmp/geoip.dat" && -f "/tmp/geosite.dat" ]]; then
    echo "      Using cached geodata from /tmp..."
    cp "/tmp/geoip.dat" "${OUTPUT_DIR}/geoip.dat"
    cp "/tmp/geosite.dat" "${OUTPUT_DIR}/geosite.dat"
elif command -v curl &> /dev/null; then
    curl -L --progress-bar -o "${OUTPUT_DIR}/geoip.dat" "${GEOIP_URL}"
    curl -L --progress-bar -o "${OUTPUT_DIR}/geosite.dat" "${GEOSITE_URL}"
    # Cache to /tmp for future package runs
    cp "${OUTPUT_DIR}/geoip.dat" /tmp/geoip.dat 2>/dev/null || true
    cp "${OUTPUT_DIR}/geosite.dat" /tmp/geosite.dat 2>/dev/null || true
elif command -v wget &> /dev/null; then
    wget -q -O "${OUTPUT_DIR}/geoip.dat" "${GEOIP_URL}"
    wget -q -O "${OUTPUT_DIR}/geosite.dat" "${GEOSITE_URL}"
else
    echo "      Warning: neither curl nor wget found. The Python launcher will auto-download geodata on startup."
fi

# 4. Copy launcher and configuration files
echo "[3/4] Copying launcher scripts and configuration templates..."
cp "${SCRIPT_DIR}/main.py" "${OUTPUT_DIR}/main.py"
cp "${SCRIPT_DIR}/app.py" "${OUTPUT_DIR}/app.py"
cp "${SCRIPT_DIR}/requirements.txt" "${OUTPUT_DIR}/requirements.txt"
cp "${SCRIPT_DIR}/env.example" "${OUTPUT_DIR}/.env.example"
cp "${SCRIPT_DIR}/config.template.yml" "${OUTPUT_DIR}/config.template.yml"

# Create initial .env if not present
cp "${SCRIPT_DIR}/env.example" "${OUTPUT_DIR}/.env"

# 5. Create ZIP package
echo "[4/4] Creating ZIP bundle..."
cd "${OUTPUT_DIR}"
if command -v zip &> /dev/null; then
    zip -q -9 -r "${ZIP_PATH}" .
else
    # Fallback to python zipfile module if zip utility is missing
    python3 -c "import zipfile, os; z = zipfile.ZipFile('${ZIP_PATH}', 'w', zipfile.ZIP_DEFLATED); [z.write(f) for f in os.listdir('.')]"
fi

# Cleanup dist directory
rm -rf "${OUTPUT_DIR}"

PACKAGE_SIZE=$(du -h "${ZIP_PATH}" | cut -f1)
echo "=========================================================="
echo " Package Created Successfully!"
echo " Output: ${ZIP_PATH} (${PACKAGE_SIZE})"
echo "=========================================================="
echo ""
echo "How to deploy on KataBump:"
echo "1. Go to control.katabump.com and open your server."
echo "2. Open the 'Files' tab and upload '${ZIP_NAME}' (drag & drop)."
echo "3. Click the three dots on '${ZIP_NAME}' and select 'Unarchive' / 'Extract'."
echo "4. Edit the '.env' file with your ArchNet Panel URL, Server ID, and Secret Key."
echo "5. In your ArchNet panel, configure the inbound to match KataBump's allocated port."
echo "6. Go to 'Console' and click 'Start'."
echo "=========================================================="
