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
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -mod=readonly -ldflags="-s -w" -o /out/turnkey-client .

# distroless/static ships /etc/ssl/certs/ca-certificates.crt, so HTTPS to the
# Turnkey API works without copying a CA bundle (the AWS Nitro attestation root
# is embedded in awsnitroverifier, separate from the system trust store).
FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160
# Key loader resolves ~/.config/turnkey/keys via os.UserHomeDir(); pin HOME so a
# mounted key dir (or one written from a CI secret) lands at a predictable path.
ENV HOME=/root
COPY --from=build /out/turnkey-client /usr/local/bin/turnkey-client
ENTRYPOINT ["/usr/local/bin/turnkey-client"]
