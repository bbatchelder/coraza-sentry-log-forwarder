# TODO

## Security Hardening

- [ ] Add Kubernetes `securityContext` to deployment manifest (`deploy/kubernetes/deployment.yaml`)
  - `runAsNonRoot: true`
  - `readOnlyRootFilesystem: true`
  - `allowPrivilegeEscalation: false`
  - `capabilities.drop: ["ALL"]`

- [ ] Change `SENTRY_DSN` in deployment template from plain `value:` to `secretKeyRef` to discourage committing real DSNs

- [ ] Cap the pending events buffer in `log-streamer.ts` to prevent unbounded growth under high WAF event volume

- [ ] Limit fatal error logging in `index.ts` to `err.message` only (full error already sent to Sentry via `captureException`)

- [ ] Document that operators should configure Sentry data scrubbing rules for PII (client IPs, matched attack payloads) to support GDPR compliance
