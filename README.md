![Image](https://img.shields.io/github/actions/workflow/status/ocsp-manager/ocsp-manager/main.yml?branch=main&style=flat-square)

# ocsp-manager

`ocsp-manager` monitors [Kubernetes](https://kubernetes.io)
[Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) of type `kubernetes.io/tls` and attempts to fetch
[OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) data to store jointly with the certificate
(along with `ca.crt`, `tls.key`, and `tls.crt`) for use by
[Ingress Controllers](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/) etc. By default,
responses are stored in the `tls.ocsp` key.

# installation

```bash
helm repo add ocsp-manager https://ocsp-manager.github.io/charts/
helm repo update

# https://github.com/ocsp-manager/charts/blob/main/stable/ocsp-manager/values.yaml
helm upgrade --install --create-namespace -n ocsp-manager --values=values-production.yaml ocsp-manager ocsp-manager/ocsp-manager

# remove
helm -n ocsp-manager uninstall ocsp-manager
```

# operation

In order to fetch an OCSP response you need 3 things:

1. a certificate
1. an OCSP responder URL
1. the CA certificate which issued the certificate

The logic for discovering each of the above items is:

1. certificate is implicit/embedded into Kubernetes Secrets
1. The OCSP responder URL is discovered (in order of preference) via the `ocsp-responder-url` annotation as set on the
Secret, otherwise it is pulled from data embedded in the certificate.
1. The CA certificate data is discovered (in order of preference) via the `ca-url` annotation as set on the Secret, next
CA data is pulled from the `ca.crt` key if present in the Secret, next we check the `tls.crt` value for the full cert
chain and pull data from there (2nd cert in the chain), lastly we fall back to the issuer URL embedded in the
certificate.

# env

- `OCSP_MANAGER_DEFAULT_RESPONSE_SECRET_KEY` - used to override the default of `tls.ocsp`
- `OCSP_MANAGER_REFRESH_INTERVAL` - period of time after `This Update` that the OCSP data should be considered stale
(defaults to 3 days), in practical terms this cannot be less than the reconcile interval for the controller
- `OCSP_MANAGER_RECONCILE_INTERVAL` - maximum period of time the controller will go before performing reconciliation
on all certs/secrets (default is 12 hours).
- `OCSP_MANAGER_SECRET_LABEL_SELECTOR` - [Label Selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors)
for the certs/secrets to operate on. Default is blank (no filtering based on labels). As an example, if you wish to
explicitly opt-in individual Secrets you could set this value to `ocsp-manager.io/enabled=true`.
- `OCSP_MANAGER_SECRET_FIELD_SELECTOR` - [Field Selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/field-selectors/)
for the certs/secrets to operate on. Default is `type=kubernetes.io/tls`. If you override you likely want to include the
default and add more (ie: `type=kubernetes.io/tls,metadata.namespace!=somenamespace`).

# annotations

Annotations are used by `ocsp-manager` to either alter the behavior of the controller or to provide additional
information to the operator. All
[annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) are in the
`ocsp-manager.io` namespace and reside on the operative cert/secret.

## set by operator

These [annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) may be set by the
operator on the [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) to adjust how `ocsp-manager`
behaves.

- `response-key` - the name of the key in the secret where the OCSP data should be stored (default is 
`OCSP_MANAGER_DEFAULT_RESPONSE_SECRET_KEY` env value or `tls.ocsp`)
- `refresh-interval` - period of time after `This Update` that the OCSP data should be considered stale (defaults to 3
days), in practical terms this cannot be less than the reconcile interval for the controller
- `ocsp-responder-url` - explicitly set the responder URL (generally this is pulled from the certificate data)
- `ca-url` - explicitly set the CA URL

## set by `ocsp-manager`

[Annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) set by `ocsp-manager` on
respective [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) to provide additional information about
the [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) response.

- `response-fetch-time` - when `ocsp-manager` fetched the current OCSP data
- `ocsp-this-update` - value of the `This Update` property of the OCSP response data (ie: when was the data issued)
- `ocsp-revoked-time` - time when the revocation occurred

# labels

## set by `ocsp-manager`

- `ocsp-is-revoked` - `true` or `false`, if present data has been fetched
- `ocsp-revoked-reason` - if revoked, the reason

# development

```bash
composer run-script buildphar
docker build -t foobar .
docker run --rm foobar
docker run --rm -ti foobar sh

# inspect ocsp binary data
openssl ocsp -respin dev/ocsp-binary-sample -text
```
