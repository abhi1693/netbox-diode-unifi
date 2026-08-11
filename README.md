# NetBox Diode UniFi Discovery

[![Container Image](https://github.com/abhi1693/netbox-diode-unifi/actions/workflows/container.yml/badge.svg)](https://github.com/abhi1693/netbox-diode-unifi/actions/workflows/container.yml)
[![Release](https://img.shields.io/github/v/release/abhi1693/netbox-diode-unifi?display_name=tag&sort=semver)](https://github.com/abhi1693/netbox-diode-unifi/releases)
[![GHCR Image](https://img.shields.io/badge/GHCR-netbox--diode--unifi-blue?logo=github)](https://github.com/abhi1693/netbox-diode-unifi/pkgs/container/netbox-diode-unifi)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-linux%2Farm64-lightgrey)](https://github.com/abhi1693/netbox-diode-unifi/actions/workflows/container.yml)

UniFi Network inventory collector for NetBox Diode.

This project discovers infrastructure data from UniFi Network APIs and sends
NetBox entities to Diode for reconciliation. It is built for branch-based
review workflows where discovered data lands in a NetBox branch first, then can
be inspected, reconciled, and merged intentionally.

## What It Discovers

The collector reads from the richer UniFi Network API paths under
`/proxy/network/api/s/<site>` and supplements them with the official
`/proxy/network/integration/v1` endpoints where useful.

It currently models:

- UniFi infrastructure devices as NetBox devices with manufacturer, role,
  platform, firmware, serial-aware identity, state, management interface, and
  primary IP data.
- Missing Ubiquiti device types through `netbox-metatype-importer` before Diode
  ingestion, using the NetBox API and branch header.
- Switch, gateway, and AP interfaces from UniFi port and uplink data, including
  media, speed, PoE, SFP module, STP, VLAN, uplink, and parent-interface detail
  where UniFi exposes it.
- Device management IPs, preferring addresses from the UniFi Default network
  because that network is treated as the management network.
- VLANs, prefixes, DHCP IP ranges, WLANs, VPN tunnels, VPN prefixes, WAN
  providers, circuits, circuit terminations, and selected cable relationships.
- LLDP/uplink cables when both endpoints are visible in the same UniFi payload.
- Infrastructure MAC addresses assigned to each device `mgmt` interface for
  stable Diode reconciliation.

Client devices are intentionally disabled by default. The collector does not
emit standalone client MAC/IP records unless client modeling is explicitly
enabled.

## Reconciliation Model

The collector emits discovered records with the `diode-discovery` and `unifi`
tags. After a successful Diode ingestion it can prune supported stale records
from the target NetBox branch when tagged objects are no longer present in the
current UniFi payload.

Current prune coverage:

- VPN tunnels
- WLANs
- IP ranges
- IP addresses
- Prefixes
- MAC addresses
- VLANs

Devices, interfaces, circuits, and cables are not pruned yet because they need
dependency-aware deletion order.

## Container Image

The production image is built by
`.github/workflows/container.yml` through the shared
`abhi1693/actions/.github/workflows/docker-build-push.yml@master` workflow.

Release images are published to GHCR:

```text
ghcr.io/abhi1693/netbox-diode-unifi:<version>
```

The image is linux/arm64, runs as UID/GID `1000`, and starts the collector with
the `netbox-diode-unifi` console script.

## Runtime Configuration

Required environment variables:

| Variable | Description |
| --- | --- |
| `UNIFI_HOST` | UniFi gateway/controller base URL, for example `https://192.168.3.1`. |
| `DIODE_CLIENT_ID` | Diode OAuth client ID. |
| `DIODE_CLIENT_SECRET` | Diode OAuth client secret. |

Optional environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `UNIFI_API_BASE_PATH` | `/proxy/network` | UniFi Network API base path. |
| `UNIFI_NETWORK_SITE` | `default` | UniFi site slug. |
| `UNIFI_VERIFY_TLS` | `false` | Verify UniFi TLS certificates. |
| `UNIFI_API_KEY` | unset | Direct UniFi API key. If unset, the collector reads the configured Kubernetes Secret. |
| `UNIFI_SECRET_NAMESPACE` | `kube-public` | Namespace for the UniFi API key Secret. |
| `UNIFI_SECRET_NAME` | `external-dns-unifi-sops` | UniFi API key Secret name. |
| `UNIFI_SECRET_KEY` | `api-key` | UniFi API key field in the Secret. |
| `UNIFI_IMPORT_DEVICE_TYPES` | `true` | Import missing device types through `netbox-metatype-importer`. |
| `UNIFI_INCLUDE_CLIENT_DEVICES` | `false` | Emit client devices and client MAC/IP records. |
| `UNIFI_PRUNE_STALE` | `true` | Remove supported tagged records absent from the current UniFi payload. |
| `UNIFI_PRUNE_MAX_DELETE` | `100` | Refuse pruning if the complete delete plan exceeds this count. |
| `UNIFI_VPN_ENDPOINTS` | built in list | Comma-separated UniFi VPN endpoint templates. Templates may use `{site}`. |
| `DIODE_TARGET` | `grpc://netbox-diode-ingress-nginx-controller.netbox.svc.cluster.local:80/diode` | Diode gRPC target. |
| `NETBOX_SITE_NAME` | `Home` | NetBox site name for discovered objects. |
| `NETBOX_SITE_SLUG` | `home` | NetBox site slug for discovered objects. |
| `NETBOX_URL` | `http://netbox.netbox.svc.cluster.local` | NetBox API base URL. |
| `NETBOX_TOKEN` | unset | NetBox API token for branch lookup, device-type import, prechecks, and stale pruning. |
| `NETBOX_BRANCH_NAME` | `diode` | NetBox Branching branch name used for API writes. |
| `NETBOX_BRANCH_IDENTIFIER` | unset | Explicit branch schema ID. When set, branch lookup by name is skipped. |

When `UNIFI_API_KEY` is not set, the collector reads the API key from the
configured Kubernetes Secret using the pod ServiceAccount token.

## Kubernetes Deployment

The primary deployment target is the `home-lab` Fleet app at:

```text
kubernetes/projects/home-automation/apps/netbox-unifi-api-discovery
```

That deployment uses the local registry mirror form:

```text
registry.home/ghcr.io/abhi1693/netbox-diode-unifi:<version>
```

The pod runs as non-root with a read-only root filesystem and uses Kubernetes
network policy to allow only the UniFi gateway, NetBox, Diode ingress, DNS, and
Kubernetes API traffic required by the collector.

## Local Development

Create an editable install with test dependencies:

```sh
python -m pip install -e '.[test]'
pytest
```

Build and smoke-test the container locally:

```sh
DOCKER_BUILDKIT=1 docker build -t netbox-diode-unifi:test .
docker run --rm --read-only --tmpfs /tmp --user 1000:1000 \
  --entrypoint python netbox-diode-unifi:test \
  -c 'import netbox_diode_unifi.discover as d; print(d.APP_NAME, d.APP_VERSION)'
```

## Operational Notes

- UniFi object names and model values are emitted as discovered. The collector
  avoids environment-specific aliases and leaves reconciliation decisions to the
  NetBox branch review process.
- Device lookups prefer discovered serial numbers and fall back to names only
  when serial lookup misses.
- Diode handles reconciliation of present objects. Stale-object deletion is a
  separate collector post-ingest step with tag and maximum-delete safeguards.
- VPN data is assembled from official VPN endpoints and detailed `networkconf`
  records because UniFi exposes different VPN shapes across controller versions.
- WAN circuit cabling is emitted only when UniFi exposes enough endpoint data to
  match a discovered local gateway WAN interface.
