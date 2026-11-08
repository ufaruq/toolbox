FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS go
FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS dockercli
FROM mcr.microsoft.com/playwright/python:v1.62.0-noble@sha256:aa81288e738725378becba5b3e06cb0f3a7f012a610e87e8d767a090ea3f740d
COPY --from=go /usr/local/go /usr/local/go
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
ENV PATH=/usr/local/go/bin:/go/bin:$PATH GOPATH=/go GOTOOLCHAIN=auto GOFLAGS=-buildvcs=false PYTHONDONTWRITEBYTECODE=1
# This isolated test runner needs Docker Engine access for sibling-container
# acceptance tests. It is never a production Toolbox image.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev git make ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY tests/browser/requirements.txt /tmp/browser-requirements.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/browser-requirements.txt
