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
    Device,
    DeviceRole,
    DeviceType,
    Entity,
    IPAddress,
    Interface,
    MACAddress,
    Manufacturer,
    Platform,
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
                metadata=filtered_metadata(uplink, ["port_idx", "uplink_mac", "uplink_device_name", "uplink_remote_port"]) | {"source": APP_NAME},
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

    entities.extend(build_client_entities(clients, home_site, seen_ips, port_by_device_mac_and_idx))
    return entities


def build_client_entities(clients, home_site, seen_ips, port_by_device_mac_and_idx):
    entities = []
    for client in clients:
        mac = normalize_mac(client.get("mac") or client.get("macAddress"))
        ip_address = ip_with_mask(client.get("ip") or client.get("ipAddress"))
        if not mac and not ip_address:
            continue
        client_name = clean_name(client.get("hostname"), client.get("name"), mac, client.get("_id"))
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
            metadata=filtered_metadata(client, ["_id", "user_id", "mac", "network_id", "site_id"]) | {"source": APP_NAME},
        )
        parent = port_by_device_mac_and_idx.get((normalize_mac(client.get("sw_mac") or client.get("last_uplink_mac")), client.get("sw_port") or client.get("last_uplink_remote_port")))
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
    entities = build_device_entities(devices, networks, clients, wlans)
    return entities, {
        "devices": len(devices),
        "clients": len(clients),
        "networks": len(networks),
        "wlans": len(wlans),
        "entities": len(entities),
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
        f"wlans={counts['wlans']} entities={counts['entities']} response={response!r}"
    )


if __name__ == "__main__":
    main()
