# Build go
FROM golang:1.25.3-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN GOEXPERIMENT=jsonv2 go mod download
RUN GOEXPERIMENT=jsonv2 go build -v -o ./output/node -trimpath -ldflags "-s -w -buildid="

# Release
FROM  alpine
# 安装必要的工具包
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/archnets/
COPY --from=builder /app/output/node /usr/local/bin

ENTRYPOINT [ "node", "server", "--config", "/etc/archnets/config.yml"]
