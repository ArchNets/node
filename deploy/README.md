# ArchNet Node Deployment Directory

This directory organizes deployment targets, configuration templates, and orchestration scripts for `archnet-node`:

| Directory | Target Platform | Deployment Model | Documentation |
| :--- | :--- | :--- | :--- |
| **[`katabump/`](katabump/)** | [KataBump](https://katabump.com) (Pterodactyl) | Native binary + Python supervisor | [KataBump Guide](katabump/README.md) |
| **[`arvan/`](arvan/)** | [Arvan Cloud](https://www.arvancloud.ir) | Kubernetes PaaS container | [Arvan Guide](arvan/README.md) |
| **[`railway/`](railway/)** | [Railway](https://railway.app) | Docker container (`railway.toml`) | [Railway Guide](railway/README.md) |

---

## Adding New Deployment Targets

When adding support for a new hosting provider or platform:
1. Create a dedicated subfolder under `deploy/<platform_name>/`.
2. Include all necessary orchestration files (`main.py`, `Dockerfile`, manifests, or packaging scripts).
3. Provide a clear `README.md` within that folder detailing prerequisites, configuration, and panel settings.
4. Update this index table.
