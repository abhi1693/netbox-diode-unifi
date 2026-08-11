# NetBox Diode UniFi Discovery

UniFi Network API inventory collector for NetBox Diode.

The collector reads UniFi inventory from the UniFi Network APIs under
`/proxy/network/api/s/<site>` and `/proxy/network/integration/v1`, then sends
NetBox entities to Diode for reconciliation into NetBox.

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

Client devices are not modeled by default, and no standalone client MAC/IP
records are emitted while client modeling is disabled. Set
`UNIFI_INCLUDE_CLIENT_DEVICES=true` only after infrastructure devices are
accurate enough to model client interfaces and their assigned addresses.

Infrastructure device MAC addresses are assigned to and selected as the primary
MAC of each device's virtual `mgmt` interface so repeated Diode runs reconcile
the same NetBox object.

No environment-specific aliases are built into the collector. UniFi names and
models are emitted as discovered.

VPN data is collected from the official VPN server and site-to-site endpoints
and enriched with detailed VPN network configuration records from
`networkconf`. Discovered OpenVPN, L2TP, WireGuard, and IPsec records create a
`UniFi VPN` tunnel group and tunnel objects. VPN pool networks and DHCP ranges
are emitted through the normal prefix and IP-range discovery, while explicit
site-to-site remote CIDRs are emitted as VPN prefixes. If UniFi exposes no VPN
records, the collector logs the skipped optional endpoints and emits no VPN
objects.

WAN circuit cabling is modeled only when UniFi exposes a matching local gateway
WAN port. The collector cables the discovered circuit termination to that
interface and logs a skip when no explicit WAN endpoint can be matched.

## Local validation

```sh
python -m pip install -e '.[test]'
pytest
```
