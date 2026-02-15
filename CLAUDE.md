# CLAUDE.md

## Tools & Preferences

- Use `podman` instead of `docker` for container builds and pushes
- Container registry: `ghcr.io/bbatchelder/coraza-sentry-log-forwarder`
- Build multi-arch manifests (linux/amd64 + linux/arm64):
  ```
  podman build --platform linux/amd64,linux/arm64 --manifest ghcr.io/bbatchelder/coraza-sentry-log-forwarder:<tag> .
  podman manifest push ghcr.io/bbatchelder/coraza-sentry-log-forwarder:<tag> docker://ghcr.io/bbatchelder/coraza-sentry-log-forwarder:<tag>
  ```
