FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils patch \
    && rm -rf /var/lib/apt/lists/*
# Upstream distribution includes the release UI; verify before extracting.
ADD --checksum=sha256:f50ac5b150e780728b0f8c5c1533e6542576ff3834f9a89d6c9921e6759f0109 https://github.com/openbao/openbao/releases/download/v2.7.2/openbao-dist-v2.7.2.tar.xz /tmp/source.tar.xz
RUN tar -xJf /tmp/source.tar.xz --strip-components=1 && rm /tmp/source.tar.xz
COPY dependencies.patch okta-jose-v4.patch /patches/
RUN patch --batch --fuzz=0 -p1 < /patches/dependencies.patch
RUN --mount=type=cache,target=/go/pkg/mod go mod vendor
RUN patch --batch --fuzz=0 -p1 < /patches/okta-jose-v4.patch
COPY jose_migration_test.go.txt vendor/github.com/okta/okta-sdk-golang/v2/okta/toolbox_jose_test.go
ENV CGO_ENABLED=0 GOMAXPROCS=2
RUN --mount=type=cache,target=/root/.cache/go-build go test -mod=vendor -count=1 ./vendor/github.com/okta/okta-sdk-golang/v2/okta
RUN --mount=type=cache,target=/root/.cache/go-build go build -mod=vendor -p=2 -trimpath -tags='ui openbao' \
    -ldflags='-X github.com/openbao/openbao/v2/internal/version.fullVersion=2.7.2 -X github.com/openbao/openbao/v2/internal/version.VersionMetadata=toolbox.1' \
    -o /out/bao . \
    && go version -m /out/bao > /out/build-info.txt \
    && ! grep -F 'github.com/go-jose/go-jose/v3' /out/build-info.txt \
    && grep -F 'github.com/go-jose/go-jose/v4' /out/build-info.txt

# Preserve upstream entrypoint, certificates, licenses, directories and UID.
FROM openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f
COPY --from=build --chmod=0755 /out/bao /usr/bin/bao
COPY --from=build /out/build-info.txt /usr/share/toolbox/openbao-build-info.txt
USER openbao
