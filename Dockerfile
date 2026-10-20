# syntax=docker/dockerfile:1
FROM golang:1.27.2-bookworm AS source
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
FROM source AS test
CMD ["go", "test", "-race", "-count=1", "./..."]
FROM source AS build
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /toolbox ./cmd/toolbox
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /toolbox /toolbox
USER 65532:65532
ENTRYPOINT ["/toolbox"]
CMD ["serve"]
