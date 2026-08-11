# NetBox Diode UniFi Discovery

UniFi Network API inventory collector for NetBox Diode.

The collector reads UniFi inventory from a UDM/UniFi Network `/integration/v1`
API endpoint and sends NetBox entities to Diode for reconciliation into NetBox.

## Runtime

The Kubernetes deployment in `home-lab` runs this package from an immutable
GitHub archive URL and provides configuration through environment variables.

Required environment variables:

- `UNIFI_HOST`, for example `https://192.168.3.1`
- `DIODE_CLIENT_ID`
- `DIODE_CLIENT_SECRET`

Optional environment variables:

- `UNIFI_API_BASE_PATH`, default `/proxy/network`
- `UNIFI_VERIFY_TLS`, default `false`
- `UNIFI_API_KEY`, direct UniFi API key
- `UNIFI_SECRET_NAMESPACE`, default `kube-public`
- `UNIFI_SECRET_NAME`, default `external-dns-unifi-sops`
- `UNIFI_SECRET_KEY`, default `api-key`
- `DIODE_TARGET`, default `grpc://netbox-diode-ingress-nginx-controller.netbox.svc.cluster.local:80/diode`
- `NETBOX_SITE_NAME`, default `Home`
- `NETBOX_SITE_SLUG`, default `home`

When `UNIFI_API_KEY` is not set, the collector reads the API key from the
configured Kubernetes Secret using its pod ServiceAccount token.

## Local validation

```sh
python -m pip install -e '.[test]'
pytest
```
