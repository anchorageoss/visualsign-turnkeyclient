# Build a small, dependency-free image of the turnkey-client CLI so smoke tests
# (e.g. parsing a transaction against a deployed VisualSign parser) need no local
# Go toolchain. Multi-stage: static binary -> distroless.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
# Honor the lockfile: download then verify module hashes against go.sum (Go also
# builds with -mod=readonly by default, failing on any go.mod/go.sum drift).
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/turnkey-client .

FROM gcr.io/distroless/static-debian12
# Key loader resolves ~/.config/turnkey/keys via os.UserHomeDir(); pin HOME so a
# mounted key dir (or one written from a CI secret) lands at a predictable path.
ENV HOME=/root
COPY --from=build /out/turnkey-client /usr/local/bin/turnkey-client
ENTRYPOINT ["/usr/local/bin/turnkey-client"]
