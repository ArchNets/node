# ArchNet Node — Arvan Cloud Deployment

This directory contains Kubernetes deployment manifests for running `archnet-node` on [Arvan Cloud Container Service](https://www.arvancloud.ir) (Kubernetes PaaS).

## Manifests

- **`arvan-node-no-singbox.yaml`**: Standalone ArchNet Node container with Ingress and ConfigMap.
- **`arvan-node.yaml`**: Dual-container setup pairing ArchNet Node with a Sing-box routing chain.

## Usage

1. Edit the ConfigMap in the manifest with your panel URL, server ID, and secret key.
2. In your ArchNet panel, configure the node with:
   - Type: `vless` (or `vmess`/`trojan`)
   - Transport: `ws`
   - Port: `8080`
   - Security: `tls`, certMode: `none` (Ingress handles TLS termination)
   - WS Path: `/archnets` (must match Ingress path in the manifest)
3. Apply to your cluster:
   ```bash
   kubectl apply -f arvan-node-no-singbox.yaml
   ```
4. Update the Ingress host to your actual Arvan-assigned domain.
