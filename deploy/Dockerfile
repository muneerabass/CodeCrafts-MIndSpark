# syntax=docker/dockerfile:1.7
# Builds the Go binaries. Targets: api, worker (includes guarddog), cli.
# cgo is required: vet's tree-sitter based parsers and xbom link C code, so the
# runtime images must provide glibc (distroless/base, python slim).
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ ./cmd/api ./cmd/worker ./cmd/depguard ./cmd/depguard-feeds

FROM gcr.io/distroless/base-debian12:nonroot AS api
COPY --from=build /out/api /usr/local/bin/api
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/api"]

# Worker runs guarddog (Python) for heuristic malware analysis of newly added
# packages. guarddog applies its own Landlock sandbox; the container adds a
# read-only rootfs, no capabilities and a non-root user (see compose.yml).
FROM python:3.13-slim-bookworm AS worker
RUN pip install --no-cache-dir "guarddog==3.2.0" \
 && useradd --uid 10001 --create-home depguard \
 && ln -s "$(python -c 'import guarddog,os;print(os.path.dirname(guarddog.__file__))')/analyzer/metadata/resources" /var/lib/guarddog-resources \
 && chown -R 10001 /var/lib/guarddog-resources/
# guarddog refreshes its top-packages lists in place (every 30 days); compose mounts a
# writable named volume over this directory (seeded from the image) so the rootfs stays read-only.
COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=build /out/depguard-feeds /usr/local/bin/depguard-feeds
USER 10001
ENV GUARDDOG_BIN=/usr/local/bin/guarddog
ENTRYPOINT ["/usr/local/bin/worker"]

FROM gcr.io/distroless/base-debian12:nonroot AS cli
COPY --from=build /out/depguard /usr/local/bin/depguard
USER nonroot
ENTRYPOINT ["/usr/local/bin/depguard"]
