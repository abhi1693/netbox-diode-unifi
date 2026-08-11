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
    Manufacturer,
    Platform,
    Site,
    VLAN,
)


APP_NAME = "home-lab-unifi-discovery"
APP_VERSION = "0.1.2"
TAGS = ["diode-discovery", "unifi"]
MANUFACTURER = Manufacturer(name="Ubiquiti", slug="ubiquiti")


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


def role_for_device(device):
    model = str(device.get("model") or "").upper()
    name = str(device.get("name") or "").upper()
    if model.startswith("UDM") or "GATEWAY" in name:
        return DeviceRole(name="Gateway", slug="gateway", color="2196f3")
    if model.startswith(("UAP", "U6", "U7")) or "AP" in name:
        return DeviceRole(name="Wireless AP", slug="wireless-ap", color="4caf50")
    return DeviceRole(name="Switch", slug="switch", color="9c27b0")


def platform_for_device(device):
    model = str(device.get("model") or "").upper()
    if model.startswith("UDM"):
        return Platform(name="UniFi OS", slug="unifi-os", manufacturer=MANUFACTURER)
    return Platform(name="UniFi Network", slug="unifi-network", manufacturer=MANUFACTURER)


def build_entities(sites, devices, clients, networks):
    home_site = site()
    entities = [Entity(site=home_site)]
    seen_ips = set()
    seen_vlans = set()

    for network in networks:
        vid = network.get("vlanId")
        if vid is None and network.get("default"):
            vid = 1
        try:
            vid = int(vid)
        except (TypeError, ValueError):
            continue
        vlan_key = (vid, network.get("name"))
        if vlan_key in seen_vlans:
            continue
        seen_vlans.add(vlan_key)
        entities.append(
            Entity(
                vlan=VLAN(
                    site=home_site,
                    vid=vid,
                    name=clean_name(network.get("name"), f"VLAN {vid}"),
                    status="active" if network.get("enabled", True) else "deprecated",
                    description="Discovered from UniFi Network API",
                    tags=TAGS,
                    metadata={"unifi_network_id": network.get("id"), "source": APP_NAME},
                )
            )
        )

    for device in devices:
        mac = normalize_mac(device.get("macAddress"))
        ip_address = ip_with_mask(device.get("ipAddress"))
        name = clean_name(device.get("name"), device.get("model"), mac)
        model = clean_name(device.get("model"), "UniFi Device")
        device_obj = Device(
            name=name,
            device_type=DeviceType(manufacturer=MANUFACTURER, model=model, slug=slugify(model)),
            role=role_for_device(device),
            platform=platform_for_device(device),
            manufacturer=MANUFACTURER,
            site=home_site,
            serial=device.get("id"),
            status="active" if str(device.get("state", "")).upper() == "ONLINE" else "offline",
            description=f"UniFi device model {model}",
            comments=f"Discovered from UniFi Network API. Firmware: {device.get('firmwareVersion') or 'unknown'}",
            tags=TAGS,
            metadata={
                "unifi_device_id": device.get("id"),
                "mac_address": mac,
                "source": APP_NAME,
            },
        )
        if ip_address:
            seen_ips.add(ip_address)
            management_interface = Interface(
                device=device_obj,
                name="mgmt",
                type="virtual",
                enabled=True,
                mgmt_only=True,
                description="UniFi management interface discovered from UniFi Network API",
                tags=TAGS,
                metadata={"unifi_device_id": device.get("id"), "source": APP_NAME},
            )
            management_ip = IPAddress(
                address=ip_address,
                status="active",
                assigned_object_interface=management_interface,
                description=f"UniFi infrastructure device management IP: {name}",
                tags=TAGS,
                metadata={"unifi_device_id": device.get("id"), "source": APP_NAME},
            )
            entities.append(Entity(interface=management_interface))
            entities.append(Entity(ip_address=management_ip))
        entities.append(Entity(device=device_obj))

    for client in clients:
        ip_address = ip_with_mask(client.get("ipAddress"))
        if not ip_address or ip_address in seen_ips:
            continue
        seen_ips.add(ip_address)
        client_name = clean_name(client.get("name"), client.get("macAddress"), client.get("id"))
        entities.append(
            Entity(
                ip_address=IPAddress(
                    address=ip_address,
                    status="active" if client.get("access", {}).get("authorized", True) else "reserved",
                    description=f"UniFi client observation: {client_name}",
                    comments=(
                        f"Client type: {client.get('type') or 'unknown'}; "
                        f"MAC: {normalize_mac(client.get('macAddress')) or 'unknown'}"
                    ),
                    tags=TAGS,
                    metadata={
                        "unifi_client_id": client.get("id"),
                        "uplink_device_id": client.get("uplinkDeviceId"),
                        "source": APP_NAME,
                    },
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


def main():
    api_key = read_unifi_api_key()
    sites = paged(api_key, "/integration/v1/sites")
    if not sites:
        raise RuntimeError("UniFi API returned no sites")
    entities = []
    total_devices = total_clients = total_networks = 0
    for unifi_site in sites:
        site_id = unifi_site.get("id")
        if not site_id:
            continue
        devices = paged(api_key, f"/integration/v1/sites/{site_id}/devices")
        clients = paged(api_key, f"/integration/v1/sites/{site_id}/clients")
        networks = paged(api_key, f"/integration/v1/sites/{site_id}/networks")
        total_devices += len(devices)
        total_clients += len(clients)
        total_networks += len(networks)
        entities.extend(build_entities(sites, devices, clients, networks))
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
    response = diode.ingest(entities, metadata={"source": APP_NAME})
    print(
        "unifi discovery ingest succeeded "
        f"sites={len(sites)} devices={total_devices} clients={total_clients} "
        f"networks={total_networks} entities={len(entities)} response={response!r}"
    )


if __name__ == "__main__":
    main()
