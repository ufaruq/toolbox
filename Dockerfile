# syntax=docker/dockerfile:1.7
FROM golang:1.27.2-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
# Optional build-only corporate proxy CA. It is never copied into either image.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=proxy_ca,required=false \
    SSL_CERT_FILE=/run/secrets/proxy_ca go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=proxy_ca,required=false \
    CGO_ENABLED=0 SSL_CERT_FILE=/run/secrets/proxy_ca go build -trimpath -ldflags="-s -w" -o /out/toolbox ./cmd/toolbox

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/toolbox /toolbox
ENV TOOLBOX_ADDR=0.0.0.0:8080
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/toolbox", "healthcheck"]
ENTRYPOINT ["/toolbox"]
