import base64
import ipaddress
import json
import os
import re
import ssl
import urllib.parse
import urllib.request

from netboxlabs.diode.sdk import DiodeClient
from netboxlabs.diode.sdk.ingester import (
    Cable,
    Circuit,
    CircuitTermination,
    CircuitType,
    Device,
    DeviceRole,
    DeviceType,
    Entity,
    GenericObject,
    IPAddress,
    Interface,
    MACAddress,
    Manufacturer,
    Platform,
    Prefix,
    Provider,
    Site,
    VLAN,
    WirelessLAN,
)


APP_NAME = "home-lab-unifi-discovery"
APP_VERSION = "0.2.0"
TAGS = ["diode-discovery", "unifi"]
UBIQUITI = Manufacturer(name="Ubiquiti", slug="ubiquiti")
UNKNOWN = Manufacturer(name="Unknown", slug="unknown")


def site():
    return Site(
        name=os.getenv("NETBOX_SITE_NAME", "Home"),
        slug=os.getenv("NETBOX_SITE_SLUG", "home"),
        status="active",
    )


def slugify(value):
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    return value or "unknown"


def clean_name(*values):
    for value in values:
        if value:
            return str(value).strip()
    return "unknown"


def normalize_mac(value):
    if not value:
        return None
    value = str(value).replace("-", ":").lower()
    return value if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", value) else None


def ip_with_mask(value):
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return f"{ip}/32" if ip.version == 4 else f"{ip}/128"


def compact_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def filtered_metadata(data, keys):
    return {key: data.get(key) for key in keys if data.get(key) is not None}


def bool_env(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def read_kubernetes_secret_key(namespace, name, key):
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    with open(token_path, "r", encoding="utf-8") as handle:
        token = handle.read().strip()
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/secrets/{name}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    ctx = ssl.create_default_context(cafile=ca_path)
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        secret = json.loads(resp.read())
    encoded = secret.get("data", {}).get(key)
    if not encoded:
        raise RuntimeError(f"secret key {namespace}/{name}:{key} is empty or missing")
    return base64.b64decode(encoded).decode().strip()


def unifi_get(api_key, path, params=None):
    host = os.environ["UNIFI_HOST"].rstrip("/")
    base_path = os.getenv("UNIFI_API_BASE_PATH", "/proxy/network").rstrip("/")
    verify_tls = os.getenv("UNIFI_VERIFY_TLS", "false").lower() == "true"
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{host}{base_path}{path}{query}"
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        return json.loads(resp.read())


def netbox_request(method, path, payload=None, token=None):
    base_url = os.getenv("NETBOX_URL", "http://netbox.netbox.svc.cluster.local").rstrip("/")
    token = token or os.getenv("NETBOX_TOKEN")
    if not token:
        return None
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Accept": "application/json", "Authorization": f"Token {token}"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{base_url}{path}", data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        return json.loads(body) if body else {}


def ensure_device_types(devices):
    token = os.getenv("NETBOX_TOKEN")
    if not token or not bool_env("UNIFI_IMPORT_DEVICE_TYPES", True):
        return {"checked": 0, "imported": 0, "missing": 0, "failed": 0}
    models = sorted({clean_name(device.get("model")) for device in devices if device.get("model")})
    result = {"checked": len(models), "imported": 0, "missing": 0, "failed": 0}
    for model in models:
        query = urllib.parse.urlencode({"manufacturer": UBIQUITI.name, "model": model, "limit": 1})
        try:
            existing = netbox_request("GET", f"/api/dcim/device-types/?{query}", token=token)
            if existing and existing.get("count", 0) > 0:
                continue
            response = netbox_request("POST", "/api/plugins/meta-types/device-type-import/", {"name": model}, token=token)
            if response and "Imported:" in response.get("message", ""):
                result["imported"] += 1
            else:
                result["missing"] += 1
                print(f"device type importer did not import model={model!r} response={response!r}")
        except Exception as exc:
            result["failed"] += 1
            print(f"device type importer failed model={model!r} error={exc}")
    return result


def paged(api_key, path):
    items = []
    offset = 0
    limit = 200
    while True:
        payload = unifi_get(api_key, path, {"offset": offset, "limit": limit})
        data = payload.get("data") or []
        items.extend(data)
        total = payload.get("totalCount")
        if not data or total is None or len(items) >= int(total):
            break
        offset += len(data)
    return items


def network_api_get(api_key, path):
    payload = unifi_get(api_key, path)
    meta = payload.get("meta", {})
    if meta.get("rc") not in (None, "ok"):
        raise RuntimeError(f"UniFi Network API error for {path}: {meta}")
    return payload.get("data") or []


def role_for_device(device):
    model = str(device.get("model") or "").upper()
    dtype = str(device.get("type") or "").lower()
    name = str(device.get("name") or "").upper()
    if dtype in {"udm", "ugw"} or model.startswith("UDM") or "GATEWAY" in name:
        return DeviceRole(name="Gateway", slug="gateway", color="2196f3")
    if dtype == "uap" or model.startswith(("UAP", "U6", "U7")) or "AP" in name:
        return DeviceRole(name="Wireless AP", slug="wireless-ap", color="4caf50")
    if dtype == "client":
        return DeviceRole(name="Network Client", slug="network-client", color="607d8b")
    return DeviceRole(name="Switch", slug="switch", color="9c27b0")


def platform_for_device(device):
    model = str(device.get("model") or "").upper()
    dtype = str(device.get("type") or "").lower()
    if dtype in {"udm", "ugw"} or model.startswith("UDM"):
        return Platform(name="UniFi OS", slug="unifi-os", manufacturer=UBIQUITI)
    return Platform(name="UniFi Network", slug="unifi-network", manufacturer=UBIQUITI)


def network_vid(network):
    if network.get("wan_vlan_enabled") and network.get("wan_vlan") is not None:
        try:
            return int(network.get("wan_vlan"))
        except (TypeError, ValueError):
            return None
    for key in ("vlanId", "vlan"):
        value = network.get(key)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    if network.get("default") or network.get("name") == "Default":
        return 1
    return None


def prefix_for_network(network, home_site=None):
    prefix = network.get("ip_subnet")
    if not prefix and network.get("wan_ip") and network.get("wan_netmask"):
        try:
            prefix = str(ipaddress.ip_network(f"{network['wan_ip']}/{network['wan_netmask']}", strict=False))
        except ValueError:
            prefix = None
    if not prefix:
        return None
    try:
        normalized = str(ipaddress.ip_network(prefix, strict=False))
    except ValueError:
        return None
    safe_keys = [
        "_id",
        "external_id",
        "purpose",
        "networkgroup",
        "wan_networkgroup",
        "gateway_type",
        "wan_type",
        "wan_vlan",
        "vlan",
        "dhcpd_enabled",
        "dhcpd_start",
        "dhcpd_stop",
        "dhcpd_leasetime",
        "domain_name",
        "igmp_snooping",
        "mdns_enabled",
        "internet_access_enabled",
    ]
    return Prefix(
        prefix=normalized,
        scope_site=home_site or site(),
        vlan=vlan_for_network(network, home_site),
        status="active" if network.get("enabled", True) else "deprecated",
        description=f"UniFi network {clean_name(network.get('name'))}",
        comments=compact_json(filtered_metadata(network, safe_keys)),
        tags=TAGS,
        metadata=filtered_metadata(network, ["_id", "external_id", "site_id"]) | {"source": APP_NAME},
    )


def vlan_for_network(network, home_site=None):
    vid = network_vid(network)
    if vid is None:
        return None
    return VLAN(
        site=home_site or site(),
        vid=vid,
        name=clean_name(network.get("name"), f"VLAN {vid}"),
        status="active" if network.get("enabled", True) else "deprecated",
        description=f"UniFi network {network.get('purpose') or network.get('management') or 'LAN'}",
        tags=TAGS,
        metadata=filtered_metadata(
            network,
            ["id", "_id", "external_id", "purpose", "management", "zoneId", "firewall_zone_id", "networkgroup"],
        )
        | {"source": APP_NAME},
    )


def interface_type_for(port):
    media = str(port.get("media") or port.get("type") or "").upper()
    try:
        speed = int(port.get("max_speed") or port.get("speed") or 0)
    except (TypeError, ValueError):
        speed = 0
    if "SFP+" in media or speed >= 10000:
        return "10gbase-x-sfpp"
    if "SFP" in media:
        return "1000base-x-sfp"
    if speed >= 2500:
        return "2.5gbase-t"
    if media in {"GE", "ETHERNET", "WIRE"} or speed:
        return "1000base-t"
    return "other"


def speed_kbps(value):
    try:
        speed = int(value or 0)
    except (TypeError, ValueError):
        return None
    return speed * 1000 if speed > 0 else None


def port_name(port):
    return clean_name(port.get("name"), port.get("ifname"), f"Port {port.get('port_idx')}")


def port_comments(port):
    keys = [
        "port_idx",
        "media",
        "op_mode",
        "up",
        "speed",
        "max_speed",
        "full_duplex",
        "is_uplink",
        "poe_mode",
        "poe_power",
        "poe_voltage",
        "poe_class",
        "sfp_vendor",
        "sfp_part",
        "sfp_serial",
        "stp_state",
        "mac_table_count",
        "last_connection",
    ]
    return f"UniFi port details: {compact_json(filtered_metadata(port, keys))}"


def device_comments(device):
    keys = [
        "version",
        "displayable_version",
        "firmwareVersion",
        "state",
        "adopted",
        "provisioned_at",
        "last_seen",
        "uptime",
        "satisfaction",
        "architecture",
        "board_rev",
        "serial",
        "features",
        "sys_stats",
        "uplink",
    ]
    return f"UniFi device details: {compact_json(filtered_metadata(device, keys))}"


def make_device(device, home_site):
    mac = normalize_mac(device.get("mac") or device.get("macAddress"))
    model = clean_name(device.get("model"), "UniFi Device")
    name = clean_name(device.get("name"), device.get("hostname"), model, mac)
    return Device(
        name=name,
        device_type=DeviceType(manufacturer=UBIQUITI, model=model, slug=slugify(model)),
        role=role_for_device(device),
        platform=platform_for_device(device),
        manufacturer=UBIQUITI,
        site=home_site,
        serial=device.get("serial") or device.get("id") or device.get("_id"),
        status="active" if str(device.get("state", "")).upper() in {"ONLINE", "1"} or device.get("state") == 1 else "offline",
        description=f"UniFi {device.get('type') or 'device'} model {model}",
        comments=device_comments(device),
        tags=TAGS,
        metadata=filtered_metadata(
            device,
            ["_id", "id", "device_id", "configurationId", "mac", "macAddress", "type", "model", "site_id"],
        )
        | {"source": APP_NAME},
    )


def build_vlan_entities(networks, home_site):
    entities = []
    by_id = {}
    seen = set()
    for network in networks:
        vlan = vlan_for_network(network, home_site)
        if vlan is None:
            continue
        key = (vlan.vid, vlan.name)
        if key not in seen:
            seen.add(key)
            entities.append(Entity(vlan=vlan))
        for network_id in (network.get("id"), network.get("_id"), network.get("external_id")):
            if network_id:
                by_id[network_id] = vlan
    return entities, by_id


def build_prefix_entities(networks, home_site):
    entities = []
    seen = set()
    for network in networks:
        prefix = prefix_for_network(network, home_site)
        if prefix is None:
            continue
        key = prefix.prefix
        if key in seen:
            continue
        seen.add(key)
        entities.append(Entity(prefix=prefix))
    return entities


def build_wan_circuit_entities(networks, home_site):
    entities = []
    seen_providers = set()
    seen_circuits = set()
    added_circuit_type = False
    circuit_type = CircuitType(
        name="Internet",
        slug="internet",
        color="2196f3",
        description="Internet access circuit discovered from UniFi WAN settings",
        tags=TAGS,
        metadata={"source": APP_NAME},
    )
    for network in networks:
        if network.get("purpose") != "wan":
            continue
        provider_name = clean_name(network.get("name"), network.get("wan_networkgroup"), "UniFi WAN")
        provider = Provider(
            name=provider_name,
            slug=slugify(provider_name),
            description="Provider inferred from UniFi WAN network",
            tags=TAGS,
            metadata=filtered_metadata(network, ["_id", "external_id", "site_id"]) | {"source": APP_NAME},
        )
        if provider_name not in seen_providers:
            seen_providers.add(provider_name)
            entities.append(Entity(provider=provider))
        capabilities = network.get("wan_provider_capabilities") or {}
        cid = clean_name(network.get("external_id"), network.get("_id"), provider_name)
        if cid in seen_circuits:
            continue
        seen_circuits.add(cid)
        circuit = Circuit(
            cid=cid,
            provider=provider,
            type=circuit_type,
            status="active" if network.get("enabled", True) else "offline",
            commit_rate=capabilities.get("download_kilobits_per_second") or capabilities.get("upload_kilobits_per_second"),
            description=f"UniFi WAN {provider_name}",
            comments=compact_json(
                filtered_metadata(
                    network,
                    [
                        "purpose",
                        "wan_networkgroup",
                        "wan_type",
                        "wan_ip",
                        "wan_gateway",
                        "wan_netmask",
                        "wan_vlan",
                        "wan_vlan_enabled",
                        "wan_load_balance_type",
                        "wan_load_balance_weight",
                        "wan_failover_priority",
                        "wan_smartq_enabled",
                    ],
                )
                | {"wan_provider_capabilities": capabilities}
            ),
            tags=TAGS,
            metadata=filtered_metadata(network, ["_id", "external_id", "site_id"]) | {"source": APP_NAME},
        )
        term = CircuitTermination(
            circuit=circuit,
            term_side="A",
            termination_site=home_site,
            port_speed=capabilities.get("download_kilobits_per_second"),
            upstream_speed=capabilities.get("upload_kilobits_per_second"),
            description=f"UniFi WAN termination for {provider_name}",
            tags=TAGS,
            metadata={"source": APP_NAME},
        )
        if not added_circuit_type:
            entities.append(Entity(circuit_type=circuit_type))
            added_circuit_type = True
        entities.append(Entity(circuit=circuit))
        entities.append(Entity(circuit_termination=term))
    return entities


def build_wireless_lan_entities(wlans, vlan_by_id, home_site):
    entities = []
    for wlan in wlans:
        ssid = wlan.get("name")
        if not ssid:
            continue
        entities.append(
            Entity(
                wireless_lan=WirelessLAN(
                    ssid=ssid,
                    status="active" if wlan.get("enabled", True) else "disabled",
                    vlan=vlan_by_id.get(wlan.get("networkconf_id")),
                    scope_site=home_site,
                    description=f"UniFi WLAN {ssid}",
                    comments=compact_json(
                        filtered_metadata(
                            wlan,
                            [
                                "_id",
                                "wlan_band",
                                "wlan_bands",
                                "hide_ssid",
                                "is_guest",
                                "pmf_mode",
                                "wpa_mode",
                                "wpa3_support",
                                "fast_roaming_enabled",
                                "bss_transition",
                                "networkconf_id",
                            ],
                        )
                    ),
                    tags=TAGS,
                    metadata=filtered_metadata(wlan, ["_id", "external_id", "networkconf_id", "site_id"]) | {"source": APP_NAME},
                )
            )
        )
    return entities


def build_device_entities(devices, networks, clients=None, wlans=None):
    home_site = site()
    clients = clients or []
    wlans = wlans or []
    entities = [Entity(site=home_site)]
    vlan_entities, vlan_by_id = build_vlan_entities(networks, home_site)
    entities.extend(vlan_entities)
    entities.extend(build_prefix_entities(networks, home_site))
    entities.extend(build_wan_circuit_entities(networks, home_site))
    entities.extend(build_wireless_lan_entities(wlans, vlan_by_id, home_site))

    device_by_mac = {}
    port_by_device_mac_and_idx = {}
    seen_ips = set()

    for device in devices:
        device_obj = make_device(device, home_site)
        device_mac = normalize_mac(device.get("mac") or device.get("macAddress"))
        if device_mac:
            device_by_mac[device_mac] = device_obj

        for port in device.get("port_table") or []:
            native_vlan = vlan_by_id.get(port.get("native_networkconf_id"))
            iface = Interface(
                device=device_obj,
                name=port_name(port),
                type=interface_type_for(port),
                enabled=bool(port.get("enable", port.get("enabled", True))),
                speed=speed_kbps(port.get("speed") or port.get("max_speed")),
                description=f"UniFi port {port.get('port_idx')} {port.get('media') or ''} speed={port.get('speed') or 'unknown'} up={port.get('up')}",
                mode="access" if native_vlan else None,
                untagged_vlan=native_vlan,
                tags=TAGS,
                metadata=filtered_metadata(
                    port,
                    [
                        "port_idx",
                        "ifname",
                        "media",
                        "op_mode",
                        "is_uplink",
                        "poe_mode",
                        "poe_caps",
                        "sfp_vendor",
                        "sfp_part",
                        "sfp_serial",
                        "native_networkconf_id",
                        "up",
                        "speed",
                        "max_speed",
                        "full_duplex",
                        "poe_power",
                        "poe_voltage",
                        "poe_class",
                        "stp_state",
                        "mac_table_count",
                        "last_connection",
                    ],
                )
                | {"source": APP_NAME},
            )
            port_by_device_mac_and_idx[(device_mac, port.get("port_idx"))] = iface
            entities.append(Entity(interface=iface))

        uplink = device.get("uplink") or {}
        parent = port_by_device_mac_and_idx.get((device_mac, uplink.get("port_idx")))
        if not parent and uplink:
            parent = Interface(
                device=device_obj,
                name=clean_name(uplink.get("name"), f"uplink-{uplink.get('port_idx')}", "uplink"),
                type=interface_type_for(uplink),
                enabled=bool(uplink.get("up", True)),
                speed=speed_kbps(uplink.get("speed") or uplink.get("max_speed")),
                description="UniFi discovered uplink interface",
                tags=TAGS,
                metadata=filtered_metadata(uplink, ["port_idx", "uplink_mac", "uplink_device_name", "uplink_remote_port", "uplink_source", "rx_errors", "tx_errors"]) | {"source": APP_NAME},
            )
            entities.append(Entity(interface=parent))

        ip_address = ip_with_mask(device.get("ip") or device.get("ipAddress"))
        if ip_address:
            seen_ips.add(ip_address)
            mgmt = Interface(
                device=device_obj,
                name="mgmt",
                type="virtual",
                enabled=True,
                parent=parent,
                mgmt_only=True,
                description=f"UniFi management interface; parent={parent.name if parent else 'unknown'}",
                tags=TAGS,
                metadata={"source": APP_NAME, "parent_discovered": bool(parent)},
            )
            mgmt_ip = IPAddress(
                address=ip_address,
                status="active",
                assigned_object_interface=mgmt,
                description=f"UniFi management IP for {device_obj.name}",
                tags=TAGS,
                metadata={"source": APP_NAME, "device_mac": device_mac},
            )
            entities.append(Entity(interface=mgmt))
            entities.append(Entity(ip_address=mgmt_ip))

        if device_mac:
            mac_obj = MACAddress(
                mac_address=device_mac,
                description=f"UniFi device MAC for {device_obj.name}",
                tags=TAGS,
                metadata={"source": APP_NAME},
            )
            entities.append(Entity(mac_address=mac_obj))
        entities.append(Entity(device=device_obj))

    entities.extend(build_cable_entities(devices, device_by_mac, port_by_device_mac_and_idx))
    entities.extend(build_client_entities(clients, home_site, seen_ips, port_by_device_mac_and_idx))
    return entities


def build_cable_entities(devices, device_by_mac, port_by_device_mac_and_idx):
    entities = []
    seen = set()
    for device in devices:
        local_mac = normalize_mac(device.get("mac") or device.get("macAddress"))
        for uplink in [device.get("uplink") or {}]:
            remote_mac = normalize_mac(uplink.get("uplink_mac"))
            local_port_idx = uplink.get("port_idx")
            remote_port_idx = uplink.get("uplink_remote_port")
            if not local_mac or not remote_mac or local_port_idx is None or remote_port_idx is None:
                continue
            local_iface = port_by_device_mac_and_idx.get((local_mac, local_port_idx))
            remote_iface = port_by_device_mac_and_idx.get((remote_mac, remote_port_idx))
            if not local_iface or not remote_iface:
                continue
            endpoint_key = tuple(sorted([(local_mac, local_port_idx), (remote_mac, remote_port_idx)]))
            if endpoint_key in seen:
                continue
            seen.add(endpoint_key)
            local_device = device_by_mac.get(local_mac)
            remote_device = device_by_mac.get(remote_mac)
            label = f"UniFi LLDP {local_device.name if local_device else local_mac} {local_iface.name} to {remote_device.name if remote_device else remote_mac} {remote_iface.name}"
            cable = Cable(
                type="cat6" if interface_type_for(uplink).endswith("base-t") else "dac-active",
                a_terminations=[GenericObject(object_interface=local_iface)],
                b_terminations=[GenericObject(object_interface=remote_iface)],
                status="connected" if uplink.get("up", True) else "planned",
                label=label[:100],
                description="Cable/link inferred from UniFi LLDP uplink data",
                comments=compact_json(filtered_metadata(uplink, ["uplink_source", "speed", "full_duplex", "rx_errors", "tx_errors"])),
                tags=TAGS,
                metadata={"source": APP_NAME, "local_mac": local_mac, "remote_mac": remote_mac},
            )
            entities.append(Entity(cable=cable))
    return entities


def build_client_entities(clients, home_site, seen_ips, port_by_device_mac_and_idx):
    entities = []
    include_devices = bool_env("UNIFI_INCLUDE_CLIENT_DEVICES", False)
    for client in clients:
        mac = normalize_mac(client.get("mac") or client.get("macAddress"))
        ip_address = ip_with_mask(client.get("ip") or client.get("ipAddress"))
        if not mac and not ip_address:
            continue
        client_name = clean_name(client.get("hostname"), client.get("name"), mac, client.get("_id"))
        parent = port_by_device_mac_and_idx.get((normalize_mac(client.get("sw_mac") or client.get("last_uplink_mac")), client.get("sw_port") or client.get("last_uplink_remote_port")))
        client_metadata = filtered_metadata(
            client,
            ["_id", "user_id", "mac", "network_id", "site_id", "network", "vlan", "is_wired", "sw_mac", "sw_port", "last_uplink_mac", "last_uplink_remote_port", "ap_mac", "essid"],
        ) | {"source": APP_NAME, "attached_to_parent_interface": bool(parent)}
        if not include_devices:
            if mac:
                entities.append(
                    Entity(
                        mac_address=MACAddress(
                            mac_address=mac,
                            description=f"UniFi observed client MAC for {client_name}",
                            tags=TAGS,
                            metadata=client_metadata,
                        )
                    )
                )
            if ip_address and ip_address not in seen_ips:
                seen_ips.add(ip_address)
                entities.append(
                    Entity(
                        ip_address=IPAddress(
                            address=ip_address,
                            status="active",
                            description=f"UniFi observed client IP for {client_name}",
                            comments=compact_json(client_metadata),
                            tags=TAGS,
                            metadata={"source": APP_NAME, "client_mac": mac},
                        )
                    )
                )
            continue
        client_device = Device(
            name=client_name,
            device_type=DeviceType(manufacturer=UNKNOWN, model="UniFi Client", slug="unifi-client"),
            role=role_for_device({"type": "client"}),
            site=home_site,
            status="active",
            description=f"UniFi observed {'wired' if client.get('is_wired') else 'wireless'} client",
            comments=compact_json(
                filtered_metadata(
                    client,
                    [
                        "hostname",
                        "name",
                        "network",
                        "vlan",
                        "is_wired",
                        "sw_mac",
                        "sw_port",
                        "last_uplink_mac",
                        "last_uplink_name",
                        "last_uplink_remote_port",
                        "ap_mac",
                        "essid",
                        "radio",
                        "os_name",
                        "dev_vendor",
                        "wired_rate_mbps",
                        "satisfaction",
                    ],
                )
            ),
            tags=TAGS,
            metadata=client_metadata,
        )
        iface = Interface(
            device=client_device,
            name="eth0" if client.get("is_wired") else "wlan0",
            type="1000base-t" if client.get("is_wired") else "virtual",
            enabled=True,
            speed=speed_kbps(client.get("wired_rate_mbps")),
            description="UniFi observed client attachment",
            tags=TAGS,
            metadata={"source": APP_NAME, "attached_to_parent_interface": bool(parent)},
        )
        entities.append(Entity(device=client_device))
        entities.append(Entity(interface=iface))
        if mac:
            entities.append(
                Entity(
                    mac_address=MACAddress(
                        mac_address=mac,
                        assigned_object_interface=iface,
                        description=f"UniFi client MAC for {client_name}",
                        tags=TAGS,
                        metadata={"source": APP_NAME},
                    )
                )
            )
        if ip_address and ip_address not in seen_ips:
            seen_ips.add(ip_address)
            entities.append(
                Entity(
                    ip_address=IPAddress(
                        address=ip_address,
                        status="active",
                        assigned_object_interface=iface,
                        description=f"UniFi client IP for {client_name}",
                        tags=TAGS,
                        metadata={"source": APP_NAME, "client_mac": mac},
                    )
                )
            )
    return entities


def read_unifi_api_key():
    if os.getenv("UNIFI_API_KEY"):
        return os.environ["UNIFI_API_KEY"].strip()
    return read_kubernetes_secret_key(
        os.getenv("UNIFI_SECRET_NAMESPACE", "kube-public"),
        os.getenv("UNIFI_SECRET_NAME", "external-dns-unifi-sops"),
        os.getenv("UNIFI_SECRET_KEY", "api-key"),
    )


def collect_entities(api_key):
    site_slug = os.getenv("UNIFI_NETWORK_SITE", "default")
    devices = network_api_get(api_key, f"/api/s/{site_slug}/stat/device")
    clients = network_api_get(api_key, f"/api/s/{site_slug}/stat/sta")
    networks = network_api_get(api_key, f"/api/s/{site_slug}/rest/networkconf")
    wlans = network_api_get(api_key, f"/api/s/{site_slug}/rest/wlanconf")
    device_type_import = ensure_device_types(devices)
    entities = build_device_entities(devices, networks, clients, wlans)
    return entities, {
        "devices": len(devices),
        "clients": len(clients),
        "networks": len(networks),
        "wlans": len(wlans),
        "entities": len(entities),
        "device_type_import": device_type_import,
    }


def main():
    api_key = read_unifi_api_key()
    entities, counts = collect_entities(api_key)
    if not entities:
        raise RuntimeError("UniFi API produced no Diode entities")
    diode = DiodeClient(
        target=os.getenv(
            "DIODE_TARGET",
            "grpc://netbox-diode-ingress-nginx-controller.netbox.svc.cluster.local:80/diode",
        ),
        app_name=APP_NAME,
        app_version=APP_VERSION,
        client_id=os.environ["DIODE_CLIENT_ID"],
        client_secret=os.environ["DIODE_CLIENT_SECRET"],
    )
    response = diode.ingest(entities, metadata={"source": APP_NAME, "mode": "unifi-network-api"})
    print(
        "unifi discovery ingest succeeded "
        f"devices={counts['devices']} clients={counts['clients']} networks={counts['networks']} "
        f"wlans={counts['wlans']} entities={counts['entities']} "
        f"device_type_import={counts['device_type_import']} response={response!r}"
    )


if __name__ == "__main__":
    main()
