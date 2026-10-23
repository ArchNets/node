#!/usr/bin/env python3
"""
ArchNet Node — KataBump / Pterodactyl Launcher
=============================================
Manages lifecycle, environment, configuration, and dependencies for running
archnet-node inside a KataBump (or any Pterodactyl-based) Python container.
"""

import os
import sys
import time
import shutil
import signal
import platform
import subprocess
import urllib.request
from pathlib import Path

LAUNCHER_VERSION = "1.0.0"
WORK_DIR = Path(__file__).resolve().parent

# Default URLs for geo-assets
GEOIP_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat"
GEOSITE_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat"
CLOUDFLARED_AMD64_URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
CLOUDFLARED_ARM64_URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"


def log(msg: str, level: str = "INFO"):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    prefix = {
        "INFO": "[INFO]",
        "WARN": "[WARN]",
        "ERROR": "[ERROR]",
        "SUCCESS": "[OK]",
    }.get(level, "[INFO]")
    print(f"{timestamp} {prefix} {msg}", flush=True)


def load_env_file(env_path: Path):
    """Zero-dependency .env file loader."""
    if not env_path.is_file():
        return
    log(f"Loading environment variables from {env_path.name}")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception as exc:
        log(f"Failed to read {env_path}: {exc}", level="WARN")


def download_file(url: str, dest: Path, desc: str):
    log(f"Downloading {desc} from {url} ...")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest.with_suffix(".tmp")
    headers = {"User-Agent": f"ArchNet-KataBump-Launcher/{LAUNCHER_VERSION}"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp_path, "wb") as out:
            shutil.copyfileobj(resp, out)
        tmp_path.replace(dest)
        log(f"{desc} downloaded successfully ({dest.stat().st_size} bytes)", level="SUCCESS")
    except Exception as exc:
        if tmp_path.exists():
            tmp_path.unlink()
        raise RuntimeError(f"Download failed for {desc}: {exc}") from exc


def ensure_executable(path: Path):
    if path.exists():
        current_mode = path.stat().st_mode
        path.chmod(current_mode | 0o755)


def ensure_binaries_and_data():
    """Validates existence of node binary and geodata files; downloads if missing."""
    node_bin = WORK_DIR / "node"
    if not node_bin.is_file():
        download_url = os.environ.get("NODE_DOWNLOAD_URL", "").strip()
        if download_url:
            log("Node binary not found. Attempting download from NODE_DOWNLOAD_URL...", level="WARN")
            download_file(download_url, node_bin, "ArchNet Node binary")
        else:
            log("CRITICAL: './node' binary not found in working directory!", level="ERROR")
            log("Please place the compiled 'node' binary (Linux AMD64) into /home/container.", level="ERROR")
            log("Or specify 'NODE_DOWNLOAD_URL' in your .env file to enable auto-download.", level="ERROR")
            sys.exit(1)

    ensure_executable(node_bin)

    # Ensure geodata files
    for filename, url in [("geoip.dat", GEOIP_URL), ("geosite.dat", GEOSITE_URL)]:
        file_path = WORK_DIR / filename
        if not file_path.is_file() or file_path.stat().st_size < 1000:
            log(f"Missing or empty {filename}, downloading...", level="WARN")
            try:
                download_file(url, file_path, filename)
            except Exception as err:
                log(f"Could not download {filename}: {err}", level="WARN")


def ensure_cloudflared():
    """Ensures cloudflared is installed if Cloudflare Tunnel is configured."""
    tunnel_token = os.environ.get("CLOUDFLARE_TUNNEL_TOKEN", "").strip()
    if not tunnel_token:
        return None

    cf_bin = WORK_DIR / "cloudflared"
    if not cf_bin.is_file():
        arch = platform.machine().lower()
        url = CLOUDFLARED_ARM64_URL if ("arm" in arch or "aarch64" in arch) else CLOUDFLARED_AMD64_URL
        log("Cloudflare Tunnel token detected, but 'cloudflared' binary is missing. Downloading...", level="INFO")
        try:
            download_file(url, cf_bin, "Cloudflare Tunnel binary")
        except Exception as exc:
            log(f"Failed to auto-download cloudflared: {exc}", level="ERROR")
            return None

    ensure_executable(cf_bin)
    return cf_bin


def generate_config_file():
    """Generates config.yml if not already created."""
    config_path = WORK_DIR / "config.yml"
    api_host = os.environ.get("API_HOST", "").strip()
    server_id = os.environ.get("SERVER_ID", "").strip()
    secret_key = os.environ.get("SECRET_KEY", "").strip()

    if not config_path.is_file():
        log("Creating default config.yml from environment variables...")
        content = f"""Log:
  Level: {os.environ.get("LOG_LEVEL", "info")}
  Output: ""
  Access: none

Api:
  ApiHost: "{api_host}"
  ServerID: {server_id or 0}
  SecretKey: "{secret_key}"
  Timeout: 30
  PerProtocolUserList: true
"""
        config_path.write_text(content, encoding="utf-8")
        log("config.yml created successfully", level="SUCCESS")


def print_banner(server_port: str):
    print("=" * 65, flush=True)
    print(f"  ArchNet Node — KataBump / Pterodactyl Launcher v{LAUNCHER_VERSION}", flush=True)
    print(f"  System: {platform.system()} {platform.machine()} | Python {platform.python_version()}", flush=True)
    print(f"  Working Dir: {WORK_DIR}", flush=True)
    print(f"  Allocated Port: {server_port}", flush=True)
    print("=" * 65, flush=True)


def main():
    # 1. Load .env file
    load_env_file(WORK_DIR / ".env")

    # 2. Check allocated port from KataBump / Pterodactyl
    server_port = (
        os.environ.get("SERVER_PORT")
        or os.environ.get("PORT")
        or "8080"
    )

    print_banner(server_port)

    # 3. Validate required ArchNet parameters
    api_host = os.environ.get("API_HOST", "").strip()
    server_id = os.environ.get("SERVER_ID", "").strip()
    secret_key = os.environ.get("SECRET_KEY", "").strip()

    if not api_host or not server_id or not secret_key:
        log("Required environment variables are missing!", level="WARN")
        log("Ensure the following are set in KataBump or in .env file:", level="WARN")
        log("  - API_HOST   (e.g. https://panel.archnets.com)")
        log("  - SERVER_ID  (e.g. 26)")
        log("  - SECRET_KEY (e.g. jtf1blry-z7b5-edg3-fwgz-6ltss5uznoat)")
        log("Continuing will fail if config.yml does not already exist.", level="WARN")

    # 4. Ensure binaries and geo data
    ensure_binaries_and_data()

    # 5. Generate config.yml if missing
    generate_config_file()

    # 6. Check for Cloudflare Tunnel
    cf_bin = ensure_cloudflared()
    tunnel_token = os.environ.get("CLOUDFLARE_TUNNEL_TOKEN", "").strip()

    # 7. Prepare child processes
    processes = []

    def signal_handler(signum, frame):
        sig_name = signal.Signals(signum).name
        log(f"Received {sig_name}, shutting down child processes...", level="INFO")
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        time.sleep(1)
        for proc in processes:
            if proc.poll() is None:
                proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Launch Cloudflare Tunnel if configured
    if cf_bin and tunnel_token:
        log("Starting Cloudflare Tunnel daemon...", level="INFO")
        cf_cmd = [str(cf_bin), "tunnel", "--no-autoupdate", "run", "--token", tunnel_token]
        cf_proc = subprocess.Popen(
            cf_cmd,
            cwd=str(WORK_DIR),
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        processes.append(cf_proc)

    # Launch ArchNet Node
    node_cmd = [str(WORK_DIR / "node"), "server", "--config", str(WORK_DIR / "config.yml")]
    log(f"Starting ArchNet Node: {' '.join(node_cmd)}", level="INFO")

    node_proc = subprocess.Popen(
        node_cmd,
        cwd=str(WORK_DIR),
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=dict(os.environ),
    )
    processes.append(node_proc)

    # Supervise processes
    while True:
        time.sleep(1)
        # Check node process
        node_code = node_proc.poll()
        if node_code is not None:
            log(f"ArchNet Node exited with code {node_code}", level="WARN" if node_code == 0 else "ERROR")
            break

        # Check cloudflared process if running
        if cf_bin and tunnel_token:
            cf_code = cf_proc.poll()
            if cf_code is not None:
                log(f"Cloudflare Tunnel exited unexpectedly with code {cf_code}", level="ERROR")
                break

    # Clean shutdown of all remaining processes
    for proc in processes:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    sys.exit(node_code if node_code is not None else 1)


if __name__ == "__main__":
    main()
