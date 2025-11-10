# ArchNets Node

An ArchNets node server based on [Xray-core](https://github.com/XTLS/Xray-core), forked and modified from [v2node](https://github.com/wyx2685/v2node).


## Features

- Full Xray-core, Hysteria2, Singbox integration
- Support for multiple protocols (VLESS, VMess, Trojan, Shadowsocks, etc.)
- Automatic TLS certificate management
- Multi-platform support (Linux, Windows, macOS, FreeBSD, Android)
- Low resource consumption
- Easy configuration and deployment

## Installation

### Quick Install (Linux)

```bash
wget -N https://raw.githubusercontent.com/archnets/node/master/scripts/install.sh && bash install.sh
```

### Manual Installation

1. Download the latest release from [Releases](https://github.com/archnets/node/releases)
2. Extract the archive
3. Run the node binary with your configuration file

## Building from Source

### Prerequisites

- Go 1.25.3 or higher
- Git

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/archnets/node.git
cd node

# Build the binary
GOEXPERIMENT=jsonv2 go build -v -o ./node -trimpath -ldflags "-s -w -buildid="
```

The `GOEXPERIMENT=jsonv2` flag is required as this project uses Go's experimental JSON v2 package.

## Configuration

Create a configuration file (e.g., `config.yml`) with your panel settings:

```yaml
panel:
  url: "https://your-panel-url.com"
  api_key: "your-api-key"
  node_id: 1
```

Run the node:

```bash
./node -c config.yml
```

## Docker Support

Docker images are automatically built and published to GitHub Container Registry (ghcr.io).

Pull the latest image:

```bash
docker pull ghcr.io/archnets/node:latest
```

Run with Docker:

```bash
docker run -d \
  --name archnets-node \
  -v /path/to/config.yml:/etc/node/config.yml \
  ghcr.io/archnets/node:latest
```

## Supported Platforms

- Linux (x86_64, ARM, ARM64, MIPS, RISC-V, s390x, PPC64)
- Windows (x86, x86_64)
- macOS (x86_64, ARM64)
- FreeBSD (x86, x86_64, ARM, ARM64)
- Android (ARM64)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the same terms as the original v2node project. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to [@wyx2685](https://github.com/wyx2685) for the original v2node implementation
- Thanks to the [Xray-core](https://github.com/XTLS/Xray-core) team for the amazing core engine
- Thanks to all contributors who help improve this project

## Credits

This project is based on the excellent work by:
- Original repository: [wyx2685/v2node](https://github.com/wyx2685/v2node)
- Original developer: [@wyx2685](https://github.com/wyx2685)

## Support

- Issues: [GitHub Issues](https://github.com/archnets/node/issues)
- Upstream: [v2node](https://github.com/wyx2685/v2node)

