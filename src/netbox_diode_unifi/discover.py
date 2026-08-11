import base64
import datetime
import ipaddress
import json
import os
import re
import ssl
import time
import urllib.error
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
    IPRange,
    Interface,
    MACAddress,
    Manufacturer,
    Platform,
    Prefix,
    Provider,
    Site,
    Tunnel,
    TunnelGroup,
    VLAN,
    WirelessLAN,
)


APP_NAME = "home-lab-unifi-discovery"
APP_VERSION = "0.2.2"
TAGS = ["diode-discovery", "unifi"]
UBIQUITI = Manufacturer(name="Ubiquiti", slug="ubiquiti")
UNKNOWN = Manufacturer(name="Unknown", slug="unknown")
SENSITIVE_LOG_KEYS = {"token", "api_key", "authorization", "password", "client_secret"}
NETBOX_BRANCH_HEADER = "X-NetBox-Branch"
_NETBOX_BRANCH_HEADER_VALUE = None
DEFAULT_UNIFI_VPN_ENDPOINTS = [
    "/api/s/{site}/rest/vpn",
    "/api/s/{site}/rest/vpnconfig",
    "/api/s/{site}/rest/wireguard",
    "/api/s/{site}/rest/ipsecvpn",
    "/v2/api/site/{site}/vpn",
    "/v2/api/site/{site}/wireguard",
]
UNIFI_DEVICE_TYPE_MODEL_BY_SHORTNAME = {
    "U6ENT": "U6 Enterprise",
    "UAPL6": "U6+",
    "UDMPRO": "UniFi Dream Machine Pro",
    "USAGGPRO": "UniFi Switch Pro Aggregation",
    "USL24PB": "UniFi Switch 24 PoE Gen2",
}
UNIFI_DEVICE_TYPE_LIBRARY_NAME_BY_SHORTNAME = {
    "U6ENT": "U6-Enterprise.yaml",
    "UAPL6": "U6+.yaml",
    "UDMPRO": "UniFi-Dream-Machine-Pro.yaml",
    "USAGGPRO": "USW-Pro-Aggregation.yaml",
    "USL24PB": "USW-24-PoE.yaml",
}


def is_sensitive_log_key(key):
    normalized = key.lower()
    if normalized.endswith("_configured") or normalized.endswith("_name"):
        return False
    return normalized in SENSITIVE_LOG_KEYS or normalized.endswith(("_token", "_api_key", "_password", "_client_secret"))


def log_event(event, level="info", **fields):
    safe_fields = {}
    for key, value in fields.items():
        if is_sensitive_log_key(key):
            safe_fields[key] = "<redacted>"
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe_fields[key] = value
        else:
            safe_fields[key] = json.loads(compact_json(value))
    payload = {
        "ts": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "level": level,
        "event": event,
        **safe_fields,
    }
    print(compact_json(payload), flush=True)


def log_exception(event, exc, **fields):
    log_event(event, level="error", error_type=exc.__class__.__name__, error=str(exc), **fields)


def entity_type_counts(entities):
    counts = {}
    for entity in entities:
        fields = entity.ListFields()
        if not fields:
            counts["empty"] = counts.get("empty", 0) + 1
            continue
        name = fields[-1][0].name
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


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


def unifi_device_type_model(device):
    raw_model = clean_name(device.get("model"), "UniFi Device")
    return UNIFI_DEVICE_TYPE_MODEL_BY_SHORTNAME.get(raw_model.upper(), raw_model)


def unifi_device_type_library_name(device):
    raw_model = clean_name(device.get("model"), "UniFi Device")
    return UNIFI_DEVICE_TYPE_LIBRARY_NAME_BY_SHORTNAME.get(raw_model.upper(), raw_model)


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


def ip_address_value(value):
    if not value:
        return None
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def network_prefix_value(network):
    prefix = network.get("ip_subnet")
    if not prefix and network.get("wan_ip") and network.get("wan_netmask"):
        try:
            prefix = str(ipaddress.ip_network(f"{network['wan_ip']}/{network['wan_netmask']}", strict=False))
        except ValueError:
            prefix = None
    if not prefix:
        return None
    try:
        return ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None


def is_default_network(network):
    return bool(network.get("default")) or network.get("name") == "Default"


def management_network_prefixes(networks):
    prefixes = []
    seen = set()
    for network in networks:
        if not is_default_network(network):
            continue
        prefix = network_prefix_value(network)
        if prefix is None:
            continue
        key = str(prefix)
        if key not in seen:
            seen.add(key)
            prefixes.append(prefix)
    return prefixes


def device_ip_candidates(device):
    candidates = []
    seen = set()

    def add(value):
        ip = ip_address_value(value)
        if ip is None:
            return
        key = str(ip)
        if key in seen:
            return
        seen.add(key)
        candidates.append(ip)

    for key in ("ip", "ipAddress", "display_ip", "connect_request_ip"):
        add(device.get(key))

    uplink = device.get("uplink")
    if isinstance(uplink, dict):
        for key in ("ip", "ipAddress", "ip_addr"):
            add(uplink.get(key))

    return candidates


def select_management_ip(device, management_prefixes):
    candidates = device_ip_candidates(device)
    for candidate in candidates:
        if any(candidate.version == prefix.version and candidate in prefix for prefix in management_prefixes):
            return ip_with_mask(candidate), str(candidate), "default_network", len(candidates)
    if candidates:
        candidate = candidates[0]
        return ip_with_mask(candidate), str(candidate), "first_valid", len(candidates)
    return None, None, "none", 0


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
    started = time.monotonic()
    log_event("kubernetes_secret_read_start", namespace=namespace, secret_name=name, key=key)
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    with open(token_path, "r", encoding="utf-8") as handle:
        token = handle.read().strip()
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/secrets/{name}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    ctx = ssl.create_default_context(cafile=ca_path)
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            secret = json.loads(resp.read())
    except Exception as exc:
        log_exception(
            "kubernetes_secret_read_failed",
            exc,
            namespace=namespace,
            secret_name=name,
            key=key,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
        raise
    encoded = secret.get("data", {}).get(key)
    if not encoded:
        raise RuntimeError(f"secret key {namespace}/{name}:{key} is empty or missing")
    log_event(
        "kubernetes_secret_read_succeeded",
        namespace=namespace,
        secret_name=name,
        key=key,
        elapsed_ms=round((time.monotonic() - started) * 1000),
    )
    return base64.b64decode(encoded).decode().strip()


def unifi_get(api_key, path, params=None):
    started = time.monotonic()
    host = os.environ["UNIFI_HOST"].rstrip("/")
    base_path = os.getenv("UNIFI_API_BASE_PATH", "/proxy/network").rstrip("/")
    verify_tls = os.getenv("UNIFI_VERIFY_TLS", "false").lower() == "true"
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{host}{base_path}{path}{query}"
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    log_event("unifi_request_start", method="GET", path=path, params=params or {}, verify_tls=verify_tls)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            body = resp.read()
            log_event(
                "unifi_request_succeeded",
                method="GET",
                path=path,
                status=resp.status,
                bytes=len(body),
                elapsed_ms=round((time.monotonic() - started) * 1000),
            )
            return json.loads(body)
    except Exception as exc:
        log_exception(
            "unifi_request_failed",
            exc,
            method="GET",
            path=path,
            params=params or {},
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
        raise


def unifi_get_optional(api_key, path, params=None):
    started = time.monotonic()
    host = os.environ["UNIFI_HOST"].rstrip("/")
    base_path = os.getenv("UNIFI_API_BASE_PATH", "/proxy/network").rstrip("/")
    verify_tls = os.getenv("UNIFI_VERIFY_TLS", "false").lower() == "true"
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{host}{base_path}{path}{query}"
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    log_event("unifi_optional_request_start", method="GET", path=path, params=params or {}, verify_tls=verify_tls)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            body = resp.read()
            log_event(
                "unifi_optional_request_succeeded",
                method="GET",
                path=path,
                status=resp.status,
                bytes=len(body),
                elapsed_ms=round((time.monotonic() - started) * 1000),
            )
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        if exc.code in {400, 404, 405}:
            log_event(
                "unifi_optional_endpoint_unavailable",
                path=path,
                status=exc.code,
                elapsed_ms=round((time.monotonic() - started) * 1000),
            )
            return None
        raise
    except Exception as exc:
        log_exception(
            "unifi_optional_request_failed",
            exc,
            method="GET",
            path=path,
            params=params or {},
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
        return None


def netbox_branch_header_value(token):
    global _NETBOX_BRANCH_HEADER_VALUE
    if _NETBOX_BRANCH_HEADER_VALUE is not None:
        return _NETBOX_BRANCH_HEADER_VALUE
    configured = os.getenv("NETBOX_BRANCH_IDENTIFIER")
    if configured:
        _NETBOX_BRANCH_HEADER_VALUE = configured.strip()
        return _NETBOX_BRANCH_HEADER_VALUE
    branch_name = os.getenv("NETBOX_BRANCH_NAME", "diode").strip()
    if not branch_name:
        _NETBOX_BRANCH_HEADER_VALUE = ""
        return _NETBOX_BRANCH_HEADER_VALUE
    query = urllib.parse.urlencode({"name": branch_name, "limit": 1})
    response = netbox_request("GET", f"/api/plugins/branching/branches/?{query}", token=token, use_branch=False)
    branch = (response.get("results") or [None])[0] if response else None
    if not branch or not branch.get("schema_id"):
        raise RuntimeError(f"NetBox branch {branch_name!r} was not found or has no schema_id")
    _NETBOX_BRANCH_HEADER_VALUE = branch["schema_id"]
    log_event("netbox_branch_resolved", branch_name=branch_name, branch_id=branch.get("id"), branch_schema_id=_NETBOX_BRANCH_HEADER_VALUE)
    return _NETBOX_BRANCH_HEADER_VALUE


def netbox_request(method, path, payload=None, token=None, use_branch=True):
    started = time.monotonic()
    base_url = os.getenv("NETBOX_URL", "http://netbox.netbox.svc.cluster.local").rstrip("/")
    token = token or os.getenv("NETBOX_TOKEN")
    if not token:
        return None
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Accept": "application/json", "Authorization": netbox_auth_header(token)}
    if use_branch:
        branch_header_value = netbox_branch_header_value(token)
        if branch_header_value:
            headers[NETBOX_BRANCH_HEADER] = branch_header_value
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{base_url}{path}", data=data, method=method, headers=headers)
    log_event("netbox_request_start", method=method, path=path, has_payload=payload is not None)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            log_event(
                "netbox_request_succeeded",
                method=method,
                path=path,
                status=resp.status,
                bytes=len(body),
                elapsed_ms=round((time.monotonic() - started) * 1000),
            )
            return json.loads(body) if body else {}
    except Exception as exc:
        fields = {"method": method, "path": path, "elapsed_ms": round((time.monotonic() - started) * 1000)}
        if hasattr(exc, "read"):
            try:
                fields["response_body"] = exc.read().decode()[:1000]
            except Exception:
                pass
        log_exception("netbox_request_failed", exc, **fields)
        raise


def netbox_auth_header(token):
    token = str(token).strip()
    if token.startswith(("Bearer ", "Token ")):
        return token
    if token.startswith("nbt_"):
        return f"Bearer {token}"
    return f"Token {token}"


def ensure_device_types(devices):
    started = time.monotonic()
    token = os.getenv("NETBOX_TOKEN")
    if not token or not bool_env("UNIFI_IMPORT_DEVICE_TYPES", True):
        log_event(
            "device_type_import_skipped",
            reason="missing_token" if not token else "disabled",
            device_count=len(devices),
        )
        return {"checked": 0, "imported": 0, "missing": 0, "failed": 0}
    device_type_specs = sorted(
        {
            (unifi_device_type_model(device), unifi_device_type_library_name(device))
            for device in devices
            if device.get("model")
        }
    )
    result = {"checked": len(device_type_specs), "imported": 0, "missing": 0, "failed": 0}
    log_event(
        "device_type_import_start",
        model_count=len(device_type_specs),
        models=[model for model, _ in device_type_specs],
        library_names=[library_name for _, library_name in device_type_specs],
    )
    for model, library_name in device_type_specs:
        query = urllib.parse.urlencode({"model": model, "limit": 1})
        try:
            existing = netbox_request("GET", f"/api/dcim/device-types/?{query}", token=token)
            if existing and existing.get("count", 0) > 0:
                log_event("device_type_import_existing", model=model)
                continue
            library_query = urllib.parse.urlencode({"name": library_name, "vendor": UBIQUITI.name, "type": "device-types", "limit": 1})
            library = netbox_request("GET", f"/api/plugins/meta-types/device-types/?{library_query}", token=token)
            record = (library.get("results") or [None])[0] if library else None
            if not record:
                result["missing"] += 1
                log_event("device_type_import_missing", level="warning", model=model, library_name=library_name, response=library)
                continue
            payload = {
                "name": record["name"],
                "vendor": record["vendor"],
                "type": record.get("type", "device-types"),
                "sha": record["sha"],
                "download_url": record.get("download_url"),
                "is_new": record.get("is_new", False),
            }
            response = netbox_request("POST", "/api/plugins/meta-types/device-type-import/", payload, token=token)
            if response and "Imported:" in response.get("message", ""):
                result["imported"] += 1
                log_event("device_type_import_imported", model=model, library_name=library_name, message=response.get("message"))
            else:
                result["missing"] += 1
                log_event("device_type_import_missing", level="warning", model=model, library_name=library_name, response=response)
        except Exception as exc:
            result["failed"] += 1
            log_exception("device_type_import_failed", exc, model=model, library_name=library_name)
    log_event(
        "device_type_import_finished",
        elapsed_ms=round((time.monotonic() - started) * 1000),
        **result,
    )
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
        log_event("unifi_api_error_response", level="error", path=path, meta=meta)
        raise RuntimeError(f"UniFi Network API error for {path}: {meta}")
    data = payload.get("data") or []
    log_event("unifi_api_data_loaded", path=path, item_count=len(data))
    return data


def network_api_get_optional(api_key, path, params=None):
    payload = unifi_get_optional(api_key, path, params)
    if not payload:
        return []
    meta = payload.get("meta", {})
    if meta.get("rc") not in (None, "ok"):
        log_event("unifi_optional_endpoint_error_response", level="warning", path=path, meta=meta)
        return []
    data = payload.get("data") or []
    log_event("unifi_optional_api_data_loaded", path=path, item_count=len(data))
    return data if isinstance(data, list) else []


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
    if is_default_network(network):
        return 1
    return None


def prefix_for_network(network, home_site=None):
    prefix = network_prefix_value(network)
    if prefix is None:
        return None
    normalized = str(prefix)
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


def ip_range_for_network(network):
    if not network.get("dhcpd_enabled"):
        log_event("ip_range_skipped", reason="dhcp_disabled", network=clean_name(network.get("name"), network.get("_id")))
        return None

    start = network.get("dhcpd_start")
    stop = network.get("dhcpd_stop")
    if not start or not stop:
        log_event(
            "ip_range_skipped",
            reason="dhcp_range_missing",
            network=clean_name(network.get("name"), network.get("_id")),
            has_start=bool(start),
            has_stop=bool(stop),
        )
        return None

    try:
        start_ip = ipaddress.ip_address(str(start))
        stop_ip = ipaddress.ip_address(str(stop))
    except ValueError:
        log_event(
            "ip_range_skipped",
            level="warning",
            reason="dhcp_range_invalid",
            network=clean_name(network.get("name"), network.get("_id")),
            start=start,
            stop=stop,
        )
        return None

    if start_ip.version != stop_ip.version or int(start_ip) > int(stop_ip):
        log_event(
            "ip_range_skipped",
            level="warning",
            reason="dhcp_range_order_invalid",
            network=clean_name(network.get("name"), network.get("_id")),
            start=start,
            stop=stop,
        )
        return None

    prefix = network_prefix_value(network)
    if prefix is not None and (start_ip not in prefix or stop_ip not in prefix):
        log_event(
            "ip_range_skipped",
            level="warning",
            reason="dhcp_range_outside_prefix",
            network=clean_name(network.get("name"), network.get("_id")),
            prefix=str(prefix),
            start=str(start_ip),
            stop=str(stop_ip),
        )
        return None

    safe_keys = [
        "_id",
        "external_id",
        "purpose",
        "networkgroup",
        "dhcpd_enabled",
        "dhcpd_start",
        "dhcpd_stop",
        "dhcpd_leasetime",
    ]
    return IPRange(
        start_address=str(start_ip),
        end_address=str(stop_ip),
        status="active" if network.get("enabled", True) else "deprecated",
        description=f"UniFi DHCP range for {clean_name(network.get('name'))}",
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


def device_serial(device):
    return device.get("serial") or device.get("id") or device.get("_id")


def make_device(device, home_site):
    mac = normalize_mac(device.get("mac") or device.get("macAddress"))
    model = unifi_device_type_model(device)
    name = clean_name(device.get("name"), device.get("hostname"), model, mac)
    return Device(
        name=name,
        device_type=DeviceType(manufacturer=UBIQUITI, model=model, slug=slugify(model)),
        role=role_for_device(device),
        platform=platform_for_device(device),
        manufacturer=UBIQUITI,
        site=home_site,
        serial=device_serial(device),
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


def build_ip_range_entities(networks):
    entities = []
    seen = set()
    for network in networks:
        ip_range = ip_range_for_network(network)
        if ip_range is None:
            continue
        key = (ip_range.start_address, ip_range.end_address)
        if key in seen:
            continue
        seen.add(key)
        entities.append(Entity(ip_range=ip_range))
    return entities


def wan_circuit_type():
    return CircuitType(
        name="Internet",
        slug="internet",
        color="2196f3",
        description="Internet access circuit discovered from UniFi WAN settings",
        tags=TAGS,
        metadata={"source": APP_NAME},
    )


def wan_provider_name(network):
    return clean_name(network.get("name"), network.get("wan_networkgroup"), "UniFi WAN")


def wan_circuit_id(network, provider_name=None):
    return clean_name(network.get("external_id"), network.get("_id"), provider_name or wan_provider_name(network))


def wan_circuit_objects(network, home_site):
    provider_name = wan_provider_name(network)
    provider = Provider(
        name=provider_name,
        slug=slugify(provider_name),
        description="Provider inferred from UniFi WAN network",
        tags=TAGS,
        metadata=filtered_metadata(network, ["_id", "external_id", "site_id"]) | {"source": APP_NAME},
    )
    capabilities = network.get("wan_provider_capabilities") or {}
    circuit_type = wan_circuit_type()
    circuit = Circuit(
        cid=wan_circuit_id(network, provider_name),
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
    return provider, circuit_type, circuit, term


def build_wan_circuit_entities(networks, home_site):
    entities = []
    seen_providers = set()
    seen_circuits = set()
    added_circuit_type = False
    circuit_type = wan_circuit_type()
    for network in networks:
        if network.get("purpose") != "wan":
            continue
        provider, _circuit_type, circuit, term = wan_circuit_objects(network, home_site)
        if provider.name not in seen_providers:
            seen_providers.add(provider.name)
            entities.append(Entity(provider=provider))
        if circuit.cid in seen_circuits:
            continue
        seen_circuits.add(circuit.cid)
        if not added_circuit_type:
            entities.append(Entity(circuit_type=circuit_type))
            added_circuit_type = True
        entities.append(Entity(circuit=circuit))
        entities.append(Entity(circuit_termination=term))
    return entities


def normalized_token_values(*values):
    tokens = set()
    for value in values:
        if value is None:
            continue
        raw = str(value).strip()
        if not raw:
            continue
        compact = re.sub(r"[^a-z0-9]+", "", raw.lower())
        if compact:
            tokens.add(compact)
    return tokens


def wan_network_tokens(network):
    return normalized_token_values(
        network.get("name"),
        network.get("wan_networkgroup"),
        network.get("networkgroup"),
        network.get("ifname"),
        network.get("interface"),
        network.get("wan_interface"),
        network.get("wan_ifname"),
        network.get("wan_port"),
    )


def port_wan_tokens(port):
    return normalized_token_values(
        port.get("name"),
        port.get("ifname"),
        port.get("port_name"),
        port.get("network_name"),
        port.get("network"),
        port.get("op_mode"),
    )


def port_looks_like_wan(port):
    values = [
        port.get("name"),
        port.get("ifname"),
        port.get("port_name"),
        port.get("network_name"),
        port.get("network"),
        port.get("op_mode"),
        port.get("purpose"),
    ]
    return any("wan" in str(value).lower() for value in values if value is not None)


def device_looks_like_gateway(device):
    values = [
        device.get("type"),
        device.get("model"),
        device.get("displayable_version"),
        device.get("name"),
    ]
    return any(token in str(value).lower() for value in values if value is not None for token in ("udm", "ugw", "uxg", "gateway"))


def find_wan_circuit_interface(network, devices, port_by_device_mac_and_idx):
    network_tokens = wan_network_tokens(network)
    candidates = []
    for device in devices:
        device_mac = normalize_mac(device.get("mac") or device.get("macAddress"))
        if not device_mac:
            continue
        for port in device.get("port_table") or []:
            port_idx = port.get("port_idx")
            iface = port_by_device_mac_and_idx.get((device_mac, port_idx))
            if iface is None:
                continue
            score = 0
            has_wan_evidence = False
            if network_tokens and network_tokens.intersection(port_wan_tokens(port)):
                score += 20
                has_wan_evidence = True
            if port_looks_like_wan(port):
                score += 10
                has_wan_evidence = True
            if device_looks_like_gateway(device):
                score += 5
            if port.get("up", True):
                score += 1
            if not has_wan_evidence:
                continue
            candidates.append((score, device.get("name") or device.get("hostname") or device_mac, port_idx, iface, device))
    if not candidates:
        return None, None
    candidates.sort(key=lambda item: (-item[0], str(item[1]), item[2] if item[2] is not None else 9999))
    return candidates[0][3], candidates[0][4]


def build_wan_circuit_cable_entities(networks, devices, home_site, port_by_device_mac_and_idx, existing_cabled_interfaces=None):
    entities = []
    seen_interfaces = set()
    existing_cabled_interfaces = existing_cabled_interfaces or set()
    for network in networks:
        if network.get("purpose") != "wan":
            continue
        _provider, _circuit_type, circuit, term = wan_circuit_objects(network, home_site)
        iface, device = find_wan_circuit_interface(network, devices, port_by_device_mac_and_idx)
        if iface is None:
            log_event(
                "wan_circuit_cable_skipped",
                reason="missing_discovered_wan_interface",
                circuit=wan_circuit_id(network),
                provider=wan_provider_name(network),
                network_id=network.get("_id") or network.get("id"),
            )
            continue
        interface_key = netbox_interface_key(iface.device.name, iface.name)
        if interface_key in existing_cabled_interfaces:
            log_event(
                "wan_circuit_cable_skipped",
                reason="endpoint_already_cabled",
                circuit=circuit.cid,
                device=iface.device.name,
                interface=iface.name,
            )
            continue
        if interface_key in seen_interfaces:
            log_event(
                "wan_circuit_cable_skipped",
                reason="duplicate_discovered_endpoint",
                circuit=circuit.cid,
                device=iface.device.name,
                interface=iface.name,
            )
            continue
        seen_interfaces.add(interface_key)
        cable = Cable(
            type="cat6" if iface.type and iface.type.endswith("base-t") else "dac-active",
            a_terminations=[GenericObject(object_circuit_termination=term)],
            b_terminations=[GenericObject(object_interface=iface)],
            status="connected" if circuit.status == "active" else "planned",
            label=f"UniFi WAN {circuit.cid} to {iface.device.name} {iface.name}"[:100],
            description="Cable/link inferred from UniFi WAN circuit and gateway port data",
            comments=compact_json(
                filtered_metadata(
                    network,
                    ["purpose", "wan_networkgroup", "wan_type", "wan_ip", "wan_gateway", "wan_vlan", "wan_vlan_enabled"],
                )
            ),
            tags=TAGS,
            metadata={
                "source": APP_NAME,
                "network_id": network.get("_id") or network.get("id"),
                "device_serial": device_serial(device) if device else None,
            },
        )
        entities.append(Entity(cable=cable))
    return entities


def configured_vpn_endpoint_paths(site_slug):
    raw = os.getenv("UNIFI_VPN_ENDPOINTS")
    templates = [item.strip() for item in raw.split(",") if item.strip()] if raw else DEFAULT_UNIFI_VPN_ENDPOINTS
    return [template.format(site=site_slug) for template in templates]


def is_vpn_config(config):
    purpose = str(config.get("purpose") or "").lower()
    vpn_type = str(first_present(config, ["vpn_type", "type", "protocol", "connection_type"]) or "").lower()
    return "vpn" in purpose or "vpn" in vpn_type or vpn_type in {"openvpn", "wireguard", "l2tp", "ipsec"}


def vpn_config_identity(config):
    name = vpn_config_name(config).casefold()
    return name, vpn_encapsulation(config) or "unknown"


def collect_official_vpn_configs(api_key, site_slug):
    sites_path = "/integration/v1/sites"
    sites = network_api_get_optional(api_key, sites_path, {"offset": 0, "limit": 200})
    matching_sites = [site for site in sites if site.get("internalReference") == site_slug or site.get("id") == site_slug]
    if not matching_sites and len(sites) == 1:
        matching_sites = sites
    if not matching_sites:
        log_event("unifi_vpn_site_not_found", level="warning", site=site_slug, site_count=len(sites))
        return []

    site_id = matching_sites[0].get("id")
    if not site_id:
        log_event("unifi_vpn_site_not_found", level="warning", site=site_slug, reason="missing_site_id")
        return []

    configs = []
    paths = [
        f"/integration/v1/sites/{site_id}/vpn/servers",
        f"/integration/v1/sites/{site_id}/vpn/site-to-site-tunnels",
    ]
    for path in paths:
        for config in network_api_get_optional(api_key, path, {"offset": 0, "limit": 200}):
            if isinstance(config, dict):
                configs.append(config | {"_unifi_endpoint": path, "_unifi_site_id": site_id})
    log_event("unifi_official_vpn_configs_loaded", site=site_slug, endpoint_count=len(paths), item_count=len(configs))
    return configs


def collect_vpn_configs(api_key, site_slug, networks=None):
    configs_by_identity = {}
    source_counts = {"networkconf": 0, "official": 0, "optional": 0}

    def add_config(config, path, source):
        if not isinstance(config, dict):
            return
        enriched = config | {"_unifi_endpoint": config.get("_unifi_endpoint") or path}
        identity = vpn_config_identity(enriched)
        existing = configs_by_identity.get(identity, {})
        merged = existing.copy()
        for key, value in enriched.items():
            if key not in merged or merged[key] in (None, "", []):
                merged[key] = value
        endpoints = list(existing.get("_unifi_endpoints") or [])
        for endpoint in [existing.get("_unifi_endpoint"), enriched.get("_unifi_endpoint")]:
            if endpoint and endpoint not in endpoints:
                endpoints.append(endpoint)
        merged["_unifi_endpoints"] = endpoints
        configs_by_identity[identity] = merged
        source_counts[source] += 1

    networkconf_path = f"/api/s/{site_slug}/rest/networkconf"
    for config in networks or []:
        if is_vpn_config(config):
            add_config(config, networkconf_path, "networkconf")

    for config in collect_official_vpn_configs(api_key, site_slug):
        add_config(config, config.get("_unifi_endpoint"), "official")

    paths = configured_vpn_endpoint_paths(site_slug)
    for path in paths:
        for config in network_api_get_optional(api_key, path):
            add_config(config, path, "optional")
    configs = list(configs_by_identity.values())
    log_event(
        "vpn_configs_loaded",
        endpoint_count=len(paths) + 3,
        item_count=len(configs),
        source_counts=source_counts,
    )
    return configs


def first_present(data, keys):
    for key in keys:
        value = data.get(key)
        if value not in (None, "", []):
            return value
    return None


def vpn_config_name(config):
    return clean_name(
        first_present(config, ["name", "display_name", "vpn_name", "connection_name", "description"]),
        first_present(config, ["_id", "id", "external_id"]),
        "UniFi VPN",
    )


def vpn_encapsulation(config):
    raw = str(first_present(config, ["protocol", "vpn_type", "type", "method", "vpn_method", "connection_type"]) or "").lower()
    if "wireguard" in raw or raw in {"wg", "wgvpn"}:
        return "wireguard"
    if "openvpn" in raw:
        return "openvpn"
    if "l2tp" in raw:
        return "l2tp"
    if "ipsec" in raw or "site-to-site" in raw or "s2s" in raw:
        return "ipsec-tunnel"
    if "gre" in raw:
        return "gre"
    return raw or None


def vpn_status(config):
    if not config.get("enabled", True):
        return "disabled"
    raw = str(first_present(config, ["status", "state", "connection_status"]) or "").lower()
    if raw in {"connected", "online", "up", "active", "1"}:
        return "active"
    if raw in {"disabled", "offline", "down", "disconnected"}:
        return "disabled"
    return "active"


def values_from_maybe_list(value):
    if value in (None, "", []):
        return []
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,\s]+", value) if part.strip()]
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, str):
                result.extend(values_from_maybe_list(item))
            elif isinstance(item, dict):
                result.extend(values_from_maybe_list(first_present(item, ["subnet", "network", "cidr", "prefix", "address"])))
        return result
    if isinstance(value, dict):
        return values_from_maybe_list(first_present(value, ["subnet", "network", "cidr", "prefix", "address"]))
    return []


def vpn_remote_prefix_values(config):
    candidates = []
    for key in [
        "remote_subnets",
        "remote_subnet",
        "remote_networks",
        "remote_network",
        "remote_cidrs",
        "remote_cidr",
        "peer_subnets",
        "peer_networks",
    ]:
        candidates.extend(values_from_maybe_list(config.get(key)))
    prefixes = []
    seen = set()
    for candidate in candidates:
        try:
            prefix = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            log_event("vpn_remote_prefix_skipped", level="warning", reason="invalid_prefix", value=candidate, vpn=vpn_config_name(config))
            continue
        key = str(prefix)
        if key in seen:
            continue
        seen.add(key)
        prefixes.append(key)
    return prefixes


def vpn_config_comments(config):
    safe_keys = [
        "_id",
        "id",
        "external_id",
        "_unifi_endpoint",
        "_unifi_endpoints",
        "_unifi_site_id",
        "name",
        "type",
        "protocol",
        "vpn_type",
        "method",
        "vpn_method",
        "enabled",
        "status",
        "state",
        "remote_ip",
        "peer_ip",
        "server",
        "remote_subnets",
        "remote_networks",
        "local_subnets",
        "local_networks",
        "wan_networkgroup",
        "networkgroup",
        "site_id",
        "purpose",
        "ip_subnet",
        "ipv6_subnet",
        "local_port",
        "openvpn_interface",
        "openvpn_local_wan_ip",
        "wireguard_interface",
        "wireguard_local_wan_ip",
        "dhcpd_start",
        "dhcpd_stop",
        "metadata",
    ]
    return f"UniFi VPN details: {compact_json(filtered_metadata(config, safe_keys))}"


def build_vpn_entities(vpn_configs):
    if not vpn_configs:
        log_event("vpn_entities_skipped", reason="no_vpn_configs")
        return []

    entities = []
    group = TunnelGroup(
        name="UniFi VPN",
        slug="unifi-vpn",
        description="VPN tunnels discovered from UniFi Network",
        tags=TAGS,
        metadata={"source": APP_NAME},
    )
    entities.append(Entity(tunnel_group=group))
    seen_tunnels = set()
    seen_prefixes = set()
    for config in vpn_configs:
        name = vpn_config_name(config)
        if name in seen_tunnels:
            continue
        seen_tunnels.add(name)
        tunnel = Tunnel(
            name=name,
            status=vpn_status(config),
            group=group,
            encapsulation=vpn_encapsulation(config),
            description=f"UniFi VPN {name}",
            comments=vpn_config_comments(config),
            tags=TAGS,
            metadata=filtered_metadata(config, ["_id", "id", "external_id", "_unifi_endpoint", "site_id"]) | {"source": APP_NAME},
        )
        entities.append(Entity(tunnel=tunnel))
        for prefix_value in vpn_remote_prefix_values(config):
            key = (name, prefix_value)
            if key in seen_prefixes:
                continue
            seen_prefixes.add(key)
            entities.append(
                Entity(
                    prefix=Prefix(
                        prefix=prefix_value,
                        status="active" if vpn_status(config) == "active" else "deprecated",
                        description=f"UniFi VPN remote network for {name}",
                        comments=vpn_config_comments(config),
                        tags=TAGS,
                        metadata=filtered_metadata(config, ["_id", "id", "external_id", "_unifi_endpoint", "site_id"]) | {"source": APP_NAME, "vpn": name},
                    )
                )
            )
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


def build_device_entities(devices, networks, clients=None, wlans=None, vpn_configs=None):
    home_site = site()
    clients = clients or []
    wlans = wlans or []
    vpn_configs = vpn_configs or []
    mgmt_prefixes = management_network_prefixes(networks)
    log_event(
        "management_network_detected",
        prefixes=[str(prefix) for prefix in mgmt_prefixes],
        source="unifi_default_network",
    )
    entities = [Entity(site=home_site)]
    vlan_entities, vlan_by_id = build_vlan_entities(networks, home_site)
    entities.extend(vlan_entities)
    entities.extend(build_prefix_entities(networks, home_site))
    entities.extend(build_ip_range_entities(networks))
    entities.extend(build_wan_circuit_entities(networks, home_site))
    entities.extend(build_vpn_entities(vpn_configs))
    entities.extend(build_wireless_lan_entities(wlans, vlan_by_id, home_site))

    device_by_mac = {}
    port_by_device_mac_and_idx = {}
    seen_ips = set()
    seen_macs = set()

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

        ip_address, selected_ip, ip_selection_reason, candidate_count = select_management_ip(device, mgmt_prefixes)
        if candidate_count:
            log_event(
                "device_management_ip_selected",
                device=device_obj.name,
                selected_ip=selected_ip,
                reason=ip_selection_reason,
                candidate_count=candidate_count,
                default_network_prefixes=[str(prefix) for prefix in mgmt_prefixes],
                selected_from_default_network=ip_selection_reason == "default_network",
            )
        mgmt = None
        mgmt_ip = None
        mac_obj = None
        if ip_address or device_mac:
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

        if ip_address:
            seen_ips.add(ip_address)
            mgmt_ip = IPAddress(
                address=ip_address,
                status="active",
                assigned_object_interface=mgmt,
                description=f"UniFi management IP for {device_obj.name}",
                tags=TAGS,
                metadata={
                    "source": APP_NAME,
                    "device_mac": device_mac,
                    "management_ip_selection": ip_selection_reason,
                    "management_network_prefixes": [str(prefix) for prefix in mgmt_prefixes],
                },
            )
            if ipaddress.ip_interface(ip_address).ip.version == 4:
                device_obj.primary_ip4.CopyFrom(mgmt_ip)
            else:
                device_obj.primary_ip6.CopyFrom(mgmt_ip)

        if device_mac:
            if device_mac not in seen_macs:
                seen_macs.add(device_mac)
                mac_obj = MACAddress(
                    mac_address=device_mac,
                    assigned_object_interface=mgmt,
                    description=f"UniFi device MAC for {device_obj.name}",
                    tags=TAGS,
                    metadata={"source": APP_NAME, "device_serial": device_serial(device)},
                )
                mgmt.primary_mac_address.CopyFrom(mac_obj)
            else:
                log_event("mac_address_skipped", reason="duplicate", mac=device_mac, owner=device_obj.name, owner_type="device")
        if mgmt:
            entities.append(Entity(interface=mgmt))
        if mgmt_ip:
            entities.append(Entity(ip_address=mgmt_ip))
        if mac_obj:
            entities.append(Entity(mac_address=mac_obj))
        entities.append(Entity(device=device_obj))

    existing_cabled_interfaces = existing_cabled_interfaces_for_cables(devices, device_by_mac, port_by_device_mac_and_idx)
    entities.extend(build_wan_circuit_cable_entities(networks, devices, home_site, port_by_device_mac_and_idx, existing_cabled_interfaces))
    entities.extend(build_cable_entities(devices, device_by_mac, port_by_device_mac_and_idx, existing_cabled_interfaces))
    entities.extend(build_client_entities(clients, home_site, seen_ips, port_by_device_mac_and_idx, seen_macs))
    return entities


def netbox_interface_key(device_name, interface_name):
    return (str(device_name), str(interface_name))


def netbox_device_lookup(device_name, serial=None):
    lookups = []
    if serial:
        lookups.append(("serial", {"serial": serial, "limit": 1}))
    if device_name:
        lookups.append(("name", {"name": device_name, "limit": 1}))
    for method, params in lookups:
        query = urllib.parse.urlencode(params)
        result = netbox_request("GET", f"/api/dcim/devices/?{query}")
        if result and result.get("results"):
            device = result["results"][0]
            log_event(
                "netbox_device_lookup_succeeded",
                method=method,
                requested_name=device_name,
                serial=serial,
                netbox_device_id=device.get("id"),
                netbox_device_name=device.get("name"),
            )
            return device
    log_event("netbox_device_lookup_missed", requested_name=device_name, serial=serial, attempted=[method for method, _ in lookups])
    return None


def netbox_interface_is_cabled(device_name, interface_name, serial=None):
    device = netbox_device_lookup(device_name, serial)
    if not device:
        return False
    query = urllib.parse.urlencode({"device_id": device.get("id"), "name": interface_name, "limit": 1})
    result = netbox_request("GET", f"/api/dcim/interfaces/?{query}")
    return bool(result and result.get("results") and result["results"][0].get("cable"))


def existing_cabled_interfaces_for_cables(devices, device_by_mac, port_by_device_mac_and_idx):
    if not os.getenv("NETBOX_TOKEN"):
        log_event("cable_precheck_skipped", reason="missing_netbox_token")
        return set()
    started = time.monotonic()
    checked = {}
    raw_device_by_mac = {
        normalize_mac(device.get("mac") or device.get("macAddress")): device
        for device in devices
        if normalize_mac(device.get("mac") or device.get("macAddress"))
    }
    for device in devices:
        local_mac = normalize_mac(device.get("mac") or device.get("macAddress"))
        uplink = device.get("uplink") or {}
        remote_mac = normalize_mac(uplink.get("uplink_mac"))
        local_port_idx = uplink.get("port_idx")
        remote_port_idx = uplink.get("uplink_remote_port")
        if not local_mac or not remote_mac or local_port_idx is None or remote_port_idx is None:
            continue
        for mac, port_idx in [(local_mac, local_port_idx), (remote_mac, remote_port_idx)]:
            device_obj = device_by_mac.get(mac)
            iface = port_by_device_mac_and_idx.get((mac, port_idx))
            if not device_obj or not iface:
                continue
            key = netbox_interface_key(device_obj.name, iface.name)
            if key in checked:
                continue
            try:
                checked[key] = netbox_interface_is_cabled(device_obj.name, iface.name, device_serial(raw_device_by_mac.get(mac, {})))
            except Exception as exc:
                checked[key] = False
                log_exception("cable_precheck_interface_failed", exc, device=device_obj.name, interface=iface.name)
    cabled = {key for key, is_cabled in checked.items() if is_cabled}
    log_event(
        "cable_precheck_finished",
        checked=len(checked),
        already_cabled=len(cabled),
        elapsed_ms=round((time.monotonic() - started) * 1000),
    )
    return cabled


def build_cable_entities(devices, device_by_mac, port_by_device_mac_and_idx, existing_cabled_interfaces=None):
    entities = []
    seen = set()
    seen_interfaces = set()
    existing_cabled_interfaces = existing_cabled_interfaces or set()
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
            local_key = netbox_interface_key(local_device.name if local_device else local_mac, local_iface.name)
            remote_key = netbox_interface_key(remote_device.name if remote_device else remote_mac, remote_iface.name)
            if local_key in existing_cabled_interfaces or remote_key in existing_cabled_interfaces:
                log_event(
                    "cable_skipped",
                    reason="endpoint_already_cabled",
                    local_device=local_key[0],
                    local_interface=local_key[1],
                    remote_device=remote_key[0],
                    remote_interface=remote_key[1],
                )
                continue
            if local_key in seen_interfaces or remote_key in seen_interfaces:
                log_event(
                    "cable_skipped",
                    reason="duplicate_discovered_endpoint",
                    local_device=local_key[0],
                    local_interface=local_key[1],
                    remote_device=remote_key[0],
                    remote_interface=remote_key[1],
                )
                continue
            seen_interfaces.update([local_key, remote_key])
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


def build_client_entities(clients, home_site, seen_ips, port_by_device_mac_and_idx, seen_macs=None):
    entities = []
    seen_macs = seen_macs if seen_macs is not None else set()
    include_devices = bool_env("UNIFI_INCLUDE_CLIENT_DEVICES", False)
    if not include_devices:
        log_event("client_entities_skipped", reason="client_device_modeling_disabled", client_count=len(clients))
        return entities
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
            if mac not in seen_macs:
                seen_macs.add(mac)
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
            else:
                log_event("mac_address_skipped", reason="duplicate", mac=mac, owner=client_name, owner_type="client")
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
        log_event("unifi_api_key_source", source="environment")
        return os.environ["UNIFI_API_KEY"].strip()
    log_event(
        "unifi_api_key_source",
        source="kubernetes_secret",
        namespace=os.getenv("UNIFI_SECRET_NAMESPACE", "kube-public"),
        secret_name=os.getenv("UNIFI_SECRET_NAME", "external-dns-unifi-sops"),
        key=os.getenv("UNIFI_SECRET_KEY", "api-key"),
    )
    return read_kubernetes_secret_key(
        os.getenv("UNIFI_SECRET_NAMESPACE", "kube-public"),
        os.getenv("UNIFI_SECRET_NAME", "external-dns-unifi-sops"),
        os.getenv("UNIFI_SECRET_KEY", "api-key"),
    )


def collect_entities(api_key):
    started = time.monotonic()
    site_slug = os.getenv("UNIFI_NETWORK_SITE", "default")
    log_event("collection_start", site=site_slug)
    devices = network_api_get(api_key, f"/api/s/{site_slug}/stat/device")
    clients = network_api_get(api_key, f"/api/s/{site_slug}/stat/sta")
    networks = network_api_get(api_key, f"/api/s/{site_slug}/rest/networkconf")
    wlans = network_api_get(api_key, f"/api/s/{site_slug}/rest/wlanconf")
    vpn_configs = collect_vpn_configs(api_key, site_slug, networks)
    device_type_import = ensure_device_types(devices)
    entities = build_device_entities(devices, networks, clients, wlans, vpn_configs)
    counts = {
        "devices": len(devices),
        "clients": len(clients),
        "networks": len(networks),
        "wlans": len(wlans),
        "vpn_configs": len(vpn_configs),
        "entities": len(entities),
        "entity_types": entity_type_counts(entities),
        "device_type_import": device_type_import,
    }
    log_event(
        "collection_finished",
        site=site_slug,
        elapsed_ms=round((time.monotonic() - started) * 1000),
        **counts,
    )
    return entities, {
        **counts,
    }


def main():
    started = time.monotonic()
    diode_target = os.getenv(
        "DIODE_TARGET",
        "grpc://netbox-diode-ingress-nginx-controller.netbox.svc.cluster.local:80/diode",
    )
    log_event(
        "run_start",
        app_name=APP_NAME,
        app_version=APP_VERSION,
        unifi_host=os.getenv("UNIFI_HOST"),
        unifi_base_path=os.getenv("UNIFI_API_BASE_PATH", "/proxy/network"),
        unifi_site=os.getenv("UNIFI_NETWORK_SITE", "default"),
        include_client_devices=bool_env("UNIFI_INCLUDE_CLIENT_DEVICES", False),
        import_device_types=bool_env("UNIFI_IMPORT_DEVICE_TYPES", True),
        netbox_url=os.getenv("NETBOX_URL", "http://netbox.netbox.svc.cluster.local"),
        netbox_token_configured=bool(os.getenv("NETBOX_TOKEN")),
        diode_target=diode_target,
    )
    try:
        api_key = read_unifi_api_key()
        entities, counts = collect_entities(api_key)
        if not entities:
            raise RuntimeError("UniFi API produced no Diode entities")
        diode = DiodeClient(
            target=diode_target,
            app_name=APP_NAME,
            app_version=APP_VERSION,
            client_id=os.environ["DIODE_CLIENT_ID"],
            client_secret=os.environ["DIODE_CLIENT_SECRET"],
        )
        log_event("diode_ingest_start", entity_count=len(entities), entity_types=counts["entity_types"])
        ingest_started = time.monotonic()
        response = diode.ingest(entities, metadata={"source": APP_NAME, "mode": "unifi-network-api"})
        log_event(
            "diode_ingest_succeeded",
            elapsed_ms=round((time.monotonic() - ingest_started) * 1000),
            response_type=response.__class__.__name__,
            response=repr(response)[:500],
        )
        log_event(
            "run_succeeded",
            elapsed_ms=round((time.monotonic() - started) * 1000),
            devices=counts["devices"],
            clients=counts["clients"],
            networks=counts["networks"],
            wlans=counts["wlans"],
            entities=counts["entities"],
            entity_types=counts["entity_types"],
            device_type_import=counts["device_type_import"],
        )
    except Exception as exc:
        log_exception("run_failed", exc, elapsed_ms=round((time.monotonic() - started) * 1000))
        raise


if __name__ == "__main__":
    main()
