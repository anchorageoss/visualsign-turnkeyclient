# Build a small, dependency-free image of the turnkey-client CLI so smoke tests
# (e.g. parsing a transaction against a deployed VisualSign parser) need no local
# Go toolchain. Multi-stage: static binary -> distroless.
# Base images pinned by digest (tag kept for readability) for reproducible,
# supply-chain-hardened builds.
FROM golang:1.25-bookworm@sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38 AS build
WORKDIR /src
COPY go.mod go.sum ./
# Honor the lockfile: download, verify module hashes against go.sum, and build
# with -mod=readonly so any go.mod/go.sum drift fails the build.
RUN go mod download && go mod verify
COPY . .

# Version info is injected at build time so the image reports a real version and
# commit instead of the dev/none defaults. Local builds keep the defaults;
# CI passes the current version and short commit hash via --build-arg.
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -mod=readonly \
    -ldflags="-s -w -X github.com/anchorageoss/visualsign-turnkeyclient/version.Version=${VERSION} -X github.com/anchorageoss/visualsign-turnkeyclient/version.Commit=${COMMIT}" \
    -o /out/turnkey-client .

# distroless/static ships /etc/ssl/certs/ca-certificates.crt, so HTTPS to the
# Turnkey API works without copying a CA bundle (the AWS Nitro attestation root
# is embedded in awsnitroverifier, separate from the system trust store).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
# Run as the distroless nonroot user (65532). The image handles private key
# material, so root is unnecessary and increases blast radius if a dependency is
# compromised. Key loader resolves ~/.config/turnkey/keys via os.UserHomeDir();
# pin HOME so a mounted key dir lands at a predictable path. Smoke tests should
# mount host keys into /home/nonroot/.config/turnkey/keys, e.g.:
#   -v ~/.config/turnkey/keys:/home/nonroot/.config/turnkey/keys:ro
USER nonroot:nonroot
ENV HOME=/home/nonroot
COPY --from=build --chown=nonroot:nonroot /out/turnkey-client /usr/local/bin/turnkey-client
ENTRYPOINT ["/usr/local/bin/turnkey-client"]
