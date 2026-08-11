# NetBox Diode UniFi Discovery

UniFi Network API inventory collector for NetBox Diode.

The collector reads UniFi inventory from the UniFi Network API under
`/proxy/network/api/s/<site>` and sends NetBox entities to Diode for
reconciliation into NetBox.

## Runtime

The Kubernetes deployment in `home-lab` runs this package from an immutable
GitHub archive URL and provides configuration through environment variables.

Required environment variables:

- `UNIFI_HOST`, for example `https://192.168.3.1`
- `DIODE_CLIENT_ID`
- `DIODE_CLIENT_SECRET`

Optional environment variables:

- `UNIFI_API_BASE_PATH`, default `/proxy/network`
- `UNIFI_NETWORK_SITE`, default `default`
- `UNIFI_VERIFY_TLS`, default `false`
- `UNIFI_API_KEY`, direct UniFi API key
- `UNIFI_SECRET_NAMESPACE`, default `kube-public`
- `UNIFI_SECRET_NAME`, default `external-dns-unifi-sops`
- `UNIFI_SECRET_KEY`, default `api-key`
- `UNIFI_IMPORT_DEVICE_TYPES`, default `true`
- `UNIFI_INCLUDE_CLIENT_DEVICES`, default `false`
- `UNIFI_VPN_ENDPOINTS`, optional comma-separated UniFi VPN endpoint templates.
  Templates may use `{site}` and default to the known legacy/v2 VPN collection
  paths. Missing endpoints are skipped because UniFi exposes VPN data
  differently across controller versions.
- `DIODE_TARGET`, default `grpc://netbox-diode-ingress-nginx-controller.netbox.svc.cluster.local:80/diode`
- `NETBOX_SITE_NAME`, default `Home`
- `NETBOX_SITE_SLUG`, default `home`
- `NETBOX_URL`, default `http://netbox.netbox.svc.cluster.local`
- `NETBOX_TOKEN`, optional NetBox API token used to import missing device
  types through `netbox-metatype-importer`

When `UNIFI_API_KEY` is not set, the collector reads the API key from the
configured Kubernetes Secret using its pod ServiceAccount token.

Client devices are not modeled by default. Client MAC/IP observations are
included as standalone records with UniFi attachment metadata; set
`UNIFI_INCLUDE_CLIENT_DEVICES=true` only after infrastructure devices are
accurate enough to avoid duplicate endpoint devices.

No environment-specific aliases are built into the collector. UniFi names and
models are emitted as discovered.

VPN data is modeled only when UniFi exposes explicit VPN configuration records.
Discovered VPN records create a `UniFi VPN` tunnel group, tunnel objects, and
remote network prefixes when remote CIDRs are present. If UniFi does not expose
VPN collections, the collector logs the skipped optional endpoints and emits no
VPN objects.

## Local validation

```sh
python -m pip install -e '.[test]'
pytest
```
