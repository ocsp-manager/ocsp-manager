# v0.3.0

Released 2026-11-19

- pin container image to `php:8.5.13-cli-alpine3.24` (php security fixes)
- update dependencies to resolve security advisories, notably:
  - `guzzlehttp/guzzle` `7.16.3`
  - `guzzlehttp/psr7` `2.13.5`
  - `phpseclib/phpseclib` `4.0.3`
  - `react/http` `1.12.0`
  - `symfony/yaml` `8.1.11`
- update `travisghansen/kubernetes-client-php` to `v0.5.0`
  - periodically re-read the service account token from disk to support token rotation (previously the token was only
    read at startup)
  - support `tokenFile` in kubeconfig users
  - fix php 8.4+ deprecation warnings when patching resources
  - **BREAKING:** kubeconfig `auth-provider` users are no longer supported (removed upstream in kubernetes 1.26), only
    relevant when running out-of-cluster, use an exec credential plugin instead
- update `travisghansen/kubernetes-controller-php` to `v0.1.14`

# v0.2.2

Released 2026-01-05

- include the secret namespace/name in webhook log messages
- properly encode the response key when used as a JSON patch path segment

# v0.2.1

Released 2026-01-05

- route webhook requests by URI path (ignoring query string)
- do not escape slashes in webhook JSON patches

# v0.2.0

Released 2026-01-05

- mutating admission webhook support (`/webhook`) to add OCSP data at the moment a Secret is created
  - `/healthz` endpoint
  - optional TLS listener
  - new options (env / cli): `OCSP_MANAGER_WEBHOOK_ENABLED` / `--webhook-enabled`, `OCSP_MANAGER_WEBHOOK_ONLY` /
    `--webhook-only`, `OCSP_MANAGER_LISTEN_TLS` / `--listen-tls`, `OCSP_MANAGER_LISTEN_HOST` / `--listen-host`,
    `OCSP_MANAGER_LISTEN_PORT` / `--listen-port`, `OCSP_MANAGER_LISTEN_PUBLIC_CERT` / `--listen-public-cert`,
    `OCSP_MANAGER_LISTEN_PRIVATE_KEY` / `--listen-private-key`
- php `8.5` (container image and phar build)
- install the `uv` pecl extension (preferred ReactPHP event loop adapter)
- container images are now built for `linux/amd64` only
- update dependencies

# v0.1.0

Released 2023-08-28

- initial release
- `ocsp-is-revoked` and `ocsp-revoked-reason` are set as labels (remaining data as annotations)
- helm install instructions
