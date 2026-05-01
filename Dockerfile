# Build go
FROM golang:1.26.1-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN GOEXPERIMENT=jsonv2 go mod download
RUN GOEXPERIMENT=jsonv2 go build -v -o ./output/node -trimpath -ldflags "-s -w -buildid="

# Download geo data files
FROM alpine AS geodata
RUN apk --no-cache add curl
WORKDIR /geodata
# Standard geo files (Loyalsoldier)
RUN curl -fsSL -o geoip.dat https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat \
    && curl -fsSL -o geosite.dat https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat
# Iran-specific geo files (Chocolate4U)
RUN curl -fsSL -o geoip_iran.dat https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geoip.dat \
    && curl -fsSL -o geosite_iran.dat https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geosite.dat

# Release
FROM  alpine
# Install necessary tools
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/archnets/
COPY --from=builder /app/output/node /usr/local/bin
COPY --from=geodata /geodata/*.dat /usr/local/bin/

ENTRYPOINT [ "node", "server", "--config", "/etc/archnets/config.yml"]
