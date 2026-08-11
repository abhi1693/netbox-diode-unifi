from netbox_diode_unifi.discover import (
    build_cable_entities,
    build_device_entities,
    build_ip_range_entities,
    build_vpn_entities,
    collect_vpn_configs,
    ensure_device_types,
    ip_with_mask,
    log_event,
    netbox_branch_header_value,
    netbox_device_lookup,
    netbox_interface_key,
    netbox_interface_is_cabled,
    netbox_auth_header,
    normalize_mac,
    prune_key,
    prune_stale_discovery_entities,
    slugify,
    unifi_device_type_library_name,
    unifi_device_type_model,
)
import json
import pytest
from netboxlabs.diode.sdk.ingester import Device, Entity, Interface, Manufacturer, Prefix, Tunnel


def entity_fields(entity):
    return [field.name for field, _ in entity.ListFields()]


def test_helpers_normalize_values():
    assert slugify("UniFi Dream Machine") == "unifi-dream-machine"
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert ip_with_mask("192.168.1.10") == "192.168.1.10/32"
    assert unifi_device_type_model({"model": "U6ENT"}) == "U6 Enterprise"
    assert unifi_device_type_model({"model": "UAPL6"}) == "U6+"
    assert unifi_device_type_model({"model": "UDMPRO"}) == "UniFi Dream Machine Pro"
    assert unifi_device_type_model({"model": "USAGGPRO"}) == "UniFi Switch Pro Aggregation"
    assert unifi_device_type_model({"model": "USL24PB"}) == "UniFi Switch 24 PoE Gen2"
    assert unifi_device_type_model({"model": "UNKNOWNMODEL"}) == "UNKNOWNMODEL"
    assert unifi_device_type_library_name({"model": "UDMPRO"}) == "UniFi-Dream-Machine-Pro.yaml"
    assert unifi_device_type_library_name({"model": "USAGGPRO"}) == "USW-Pro-Aggregation.yaml"
    assert unifi_device_type_library_name({"model": "UNKNOWNMODEL"}) == "UNKNOWNMODEL"


def test_log_event_redacts_sensitive_fields(capsys):
    log_event(
        "test_event",
        token="secret-token",
        api_key="secret-api-key",
        netbox_token_configured=True,
        secret_name="safe-secret-name",
        safe="visible",
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["event"] == "test_event"
    assert payload["token"] == "<redacted>"
    assert payload["api_key"] == "<redacted>"
    assert payload["netbox_token_configured"] is True
    assert payload["secret_name"] == "safe-secret-name"
    assert payload["safe"] == "visible"


def test_netbox_auth_header_preserves_modern_and_legacy_tokens():
    assert netbox_auth_header("Bearer nbt_example.secret") == "Bearer nbt_example.secret"
    assert netbox_auth_header("nbt_example.secret") == "Bearer nbt_example.secret"
    assert netbox_auth_header("Token abc123") == "Token abc123"
    assert netbox_auth_header("abc123") == "Token abc123"


def test_netbox_branch_header_value_resolves_schema_id(monkeypatch):
    calls = []

    def fake_netbox_request(method, path, payload=None, token=None, use_branch=True):
        calls.append((method, path, payload, token, use_branch))
        return {"results": [{"id": 6, "name": "diode", "schema_id": "k5kvmgkt"}]}

    monkeypatch.delenv("NETBOX_BRANCH_IDENTIFIER", raising=False)
    monkeypatch.setenv("NETBOX_BRANCH_NAME", "diode")
    monkeypatch.setattr("netbox_diode_unifi.discover._NETBOX_BRANCH_HEADER_VALUE", None)
    monkeypatch.setattr("netbox_diode_unifi.discover.netbox_request", fake_netbox_request)

    assert netbox_branch_header_value("nbt_example.secret") == "k5kvmgkt"
    assert calls == [
        (
            "GET",
            "/api/plugins/branching/branches/?name=diode&limit=1",
            None,
            "nbt_example.secret",
            False,
        )
    ]


def test_ensure_device_types_uses_mapped_unifi_device_type_name(monkeypatch):
    calls = []

    def fake_netbox_request(method, path, payload=None, token=None):
        calls.append((method, path, payload, token))
        return {"count": 1}

    monkeypatch.setenv("NETBOX_TOKEN", "nbt_example.secret")
    monkeypatch.setattr("netbox_diode_unifi.discover.netbox_request", fake_netbox_request)

    assert ensure_device_types([{"model": "UDMPRO"}]) == {
        "checked": 1,
        "imported": 0,
        "missing": 0,
        "failed": 0,
    }
    assert calls == [
        ("GET", "/api/dcim/device-types/?model=UniFi+Dream+Machine+Pro&limit=1", None, "nbt_example.secret")
    ]


def test_ensure_device_types_imports_mapped_unifi_device_type_name(monkeypatch):
    calls = []

    def fake_netbox_request(method, path, payload=None, token=None):
        calls.append((method, path, payload, token))
        if method == "GET":
            if path.startswith("/api/plugins/meta-types/device-types/"):
                return {
                    "count": 1,
                    "results": [
                        {
                            "name": "USW-Pro-Aggregation.yaml",
                            "vendor": "Ubiquiti",
                            "type": "device-types",
                            "sha": "abc123",
                            "download_url": None,
                            "is_new": True,
                        }
                    ],
                }
            return {"count": 0, "results": []}
        return {"message": "Imported: USW-Pro-Aggregation.yaml"}

    monkeypatch.setenv("NETBOX_TOKEN", "nbt_example.secret")
    monkeypatch.setattr("netbox_diode_unifi.discover.netbox_request", fake_netbox_request)

    assert ensure_device_types([{"model": "USAGGPRO"}]) == {
        "checked": 1,
        "imported": 1,
        "missing": 0,
        "failed": 0,
    }
    assert calls == [
        ("GET", "/api/dcim/device-types/?model=UniFi+Switch+Pro+Aggregation&limit=1", None, "nbt_example.secret"),
        (
            "GET",
            "/api/plugins/meta-types/device-types/?name=USW-Pro-Aggregation.yaml&vendor=Ubiquiti&type=device-types&limit=1",
            None,
            "nbt_example.secret",
        ),
        (
            "POST",
            "/api/plugins/meta-types/device-type-import/",
            {
                "name": "USW-Pro-Aggregation.yaml",
                "vendor": "Ubiquiti",
                "type": "device-types",
                "sha": "abc123",
                "download_url": None,
                "is_new": True,
            },
            "nbt_example.secret",
        ),
    ]


def test_netbox_device_lookup_prefers_serial_before_name(monkeypatch):
    calls = []

    def fake_netbox_request(method, path, payload=None, token=None):
        calls.append(path)
        if "serial=SER123" in path:
            return {"results": [{"id": 42, "name": "Renamed Switch", "serial": "SER123"}]}
        return {"results": []}

    monkeypatch.setattr("netbox_diode_unifi.discover.netbox_request", fake_netbox_request)

    assert netbox_device_lookup("Old Switch", "SER123") == {"id": 42, "name": "Renamed Switch", "serial": "SER123"}
    assert calls == ["/api/dcim/devices/?serial=SER123&limit=1"]


def test_netbox_device_lookup_falls_back_to_name_when_serial_missing(monkeypatch):
    calls = []

    def fake_netbox_request(method, path, payload=None, token=None):
        calls.append(path)
        if "name=Old+Switch" in path:
            return {"results": [{"id": 43, "name": "Old Switch", "serial": ""}]}
        return {"results": []}

    monkeypatch.setattr("netbox_diode_unifi.discover.netbox_request", fake_netbox_request)

    assert netbox_device_lookup("Old Switch", "SER123") == {"id": 43, "name": "Old Switch", "serial": ""}
    assert calls == [
        "/api/dcim/devices/?serial=SER123&limit=1",
        "/api/dcim/devices/?name=Old+Switch&limit=1",
    ]


def test_netbox_interface_cable_lookup_uses_serial_resolved_device_id(monkeypatch):
    calls = []

    def fake_netbox_request(method, path, payload=None, token=None):
        calls.append(path)
        if path == "/api/dcim/devices/?serial=SER123&limit=1":
            return {"results": [{"id": 42, "name": "Renamed Switch", "serial": "SER123"}]}
        if path == "/api/dcim/interfaces/?device_id=42&name=SFP+1&limit=1":
            return {"results": [{"id": 99, "name": "SFP 1", "cable": 10}]}
        return {"results": []}

    monkeypatch.setattr("netbox_diode_unifi.discover.netbox_request", fake_netbox_request)

    assert netbox_interface_is_cabled("Old Switch", "SFP 1", "SER123") is True
    assert calls == [
        "/api/dcim/devices/?serial=SER123&limit=1",
        "/api/dcim/interfaces/?device_id=42&name=SFP+1&limit=1",
    ]


def test_build_cable_entities_skips_existing_cabled_endpoint():
    manufacturer = Manufacturer(name="Ubiquiti", slug="ubiquiti")
    local_device = Device(name="USW-24-PoE", device_type="USL24PB", manufacturer=manufacturer)
    remote_device = Device(name="USW Pro Aggregation", device_type="USAGGPRO", manufacturer=manufacturer)
    local_iface = Interface(device=local_device, name="SFP 1", type="1000base-x-sfp")
    remote_iface = Interface(device=remote_device, name="SFP+ 1", type="10gbase-x-sfpp")

    entities = build_cable_entities(
        devices=[
            {
                "mac": "aa:bb:cc:dd:ee:ff",
                "uplink": {
                    "port_idx": 1,
                    "uplink_mac": "11:22:33:44:55:66",
                    "uplink_remote_port": 1,
                },
            }
        ],
        device_by_mac={
            "aa:bb:cc:dd:ee:ff": local_device,
            "11:22:33:44:55:66": remote_device,
        },
        port_by_device_mac_and_idx={
            ("aa:bb:cc:dd:ee:ff", 1): local_iface,
            ("11:22:33:44:55:66", 1): remote_iface,
        },
        existing_cabled_interfaces={netbox_interface_key("USW-24-PoE", "SFP 1")},
    )

    assert entities == []


def test_build_cable_entities_skips_duplicate_discovered_endpoint():
    manufacturer = Manufacturer(name="Ubiquiti", slug="ubiquiti")
    aggregation = Device(name="USW Pro Aggregation", device_type="USAGGPRO", manufacturer=manufacturer)
    switch_a = Device(name="Switch A", device_type="USL24PB", manufacturer=manufacturer)
    switch_b = Device(name="Switch B", device_type="USL24PB", manufacturer=manufacturer)

    aggregation_iface = Interface(device=aggregation, name="SFP+ 1", type="10gbase-x-sfpp")
    switch_a_iface = Interface(device=switch_a, name="SFP 1", type="1000base-x-sfp")
    switch_b_iface = Interface(device=switch_b, name="SFP 1", type="1000base-x-sfp")

    entities = build_cable_entities(
        devices=[
            {
                "mac": "aa:aa:aa:aa:aa:aa",
                "uplink": {
                    "port_idx": 1,
                    "uplink_mac": "cc:cc:cc:cc:cc:cc",
                    "uplink_remote_port": 1,
                },
            },
            {
                "mac": "bb:bb:bb:bb:bb:bb",
                "uplink": {
                    "port_idx": 1,
                    "uplink_mac": "cc:cc:cc:cc:cc:cc",
                    "uplink_remote_port": 1,
                },
            },
        ],
        device_by_mac={
            "aa:aa:aa:aa:aa:aa": switch_a,
            "bb:bb:bb:bb:bb:bb": switch_b,
            "cc:cc:cc:cc:cc:cc": aggregation,
        },
        port_by_device_mac_and_idx={
            ("aa:aa:aa:aa:aa:aa", 1): switch_a_iface,
            ("bb:bb:bb:bb:bb:bb", 1): switch_b_iface,
            ("cc:cc:cc:cc:cc:cc", 1): aggregation_iface,
        },
    )

    assert len(entities) == 1


def test_build_device_entities_assigns_mgmt_interface_to_physical_parent():
    entities = build_device_entities(
        devices=[
            {
                "_id": "dev1",
                "name": "AP Test",
                "model": "U7-Pro",
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "192.168.1.10",
                "state": 1,
                "version": "1.0.0",
                "type": "uap",
                "uplink": {
                    "port_idx": 1,
                    "name": "eth0",
                    "type": "wire",
                    "speed": 1000,
                    "uplink_mac": "11:22:33:44:55:66",
                    "uplink_remote_port": 12,
                },
            }
        ],
        clients=[],
        networks=[],
        wlans=[],
    )

    assert "interface" in [entity_fields(entity)[-1] for entity in entities]
    assert "ip_address" in [entity_fields(entity)[-1] for entity in entities]

    ip_entity = next(entity for entity in entities if "ip_address" in entity_fields(entity))
    assert ip_entity.ip_address.address == "192.168.1.10/32"
    assert ip_entity.ip_address.assigned_object_interface.name == "mgmt"
    assert ip_entity.ip_address.assigned_object_interface.device.name == "AP Test"
    assert ip_entity.ip_address.assigned_object_interface.parent.name == "eth0"
    mac_entity = next(entity for entity in entities if "mac_address" in entity_fields(entity))
    assert mac_entity.mac_address.assigned_object_interface.name == "mgmt"
    assert mac_entity.mac_address.assigned_object_interface.device.name == "AP Test"
    assert mac_entity.mac_address.assigned_object_interface.parent.name == "eth0"
    mgmt_entity = next(
        entity for entity in entities if "interface" in entity_fields(entity) and entity.interface.name == "mgmt"
    )
    assert mgmt_entity.interface.primary_mac_address.mac_address == "aa:bb:cc:dd:ee:ff"


def test_build_device_entities_uses_mapped_device_type_model():
    entities = build_device_entities(
        devices=[
            {
                "_id": "dev1",
                "name": "UDM-Pro",
                "model": "UDMPRO",
                "mac": "AA:BB:CC:DD:EE:FF",
                "state": 1,
                "type": "udm",
            }
        ],
        clients=[],
        networks=[],
        wlans=[],
    )

    device_entity = next(entity for entity in entities if "device" in entity_fields(entity))
    assert device_entity.device.device_type.model == "UniFi Dream Machine Pro"
    assert device_entity.device.device_type.slug == "unifi-dream-machine-pro"


def test_build_device_entities_prefers_default_network_ip_for_primary_ip(capsys):
    entities = build_device_entities(
        devices=[
            {
                "_id": "dev1",
                "name": "Switch Test",
                "model": "USW-Test",
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "10.10.10.20",
                "ipAddress": "192.168.1.10",
                "state": 1,
                "type": "usw",
            }
        ],
        clients=[],
        networks=[
            {
                "_id": "network1",
                "name": "Default",
                "default": True,
                "ip_subnet": "192.168.1.0/24",
            }
        ],
        wlans=[],
    )

    ip_entity = next(entity for entity in entities if "ip_address" in entity_fields(entity))
    device_entity = next(entity for entity in entities if "device" in entity_fields(entity))

    assert ip_entity.ip_address.address == "192.168.1.10/32"
    assert device_entity.device.primary_ip4.address == "192.168.1.10/32"

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    selection_log = next(log for log in logs if log["event"] == "device_management_ip_selected")
    assert selection_log["reason"] == "default_network"
    assert selection_log["selected_ip"] == "192.168.1.10"
    assert selection_log["selected_from_default_network"] is True


def test_build_ip_range_entities_adds_unifi_dhcp_range():
    entities = build_ip_range_entities(
        [
            {
                "_id": "network1",
                "name": "Default",
                "ip_subnet": "192.168.1.0/24",
                "dhcpd_enabled": True,
                "dhcpd_start": "192.168.1.6",
                "dhcpd_stop": "192.168.1.254",
                "dhcpd_leasetime": 86400,
            }
        ]
    )

    assert [entity_fields(entity)[-1] for entity in entities] == ["ip_range"]
    ip_range = entities[0].ip_range
    assert ip_range.start_address == "192.168.1.6"
    assert ip_range.end_address == "192.168.1.254"
    assert ip_range.status == "active"
    assert ip_range.description == "UniFi DHCP range for Default"


def test_build_ip_range_entities_skips_missing_unifi_dhcp_range(capsys):
    entities = build_ip_range_entities(
        [
            {
                "_id": "network1",
                "name": "Default",
                "ip_subnet": "192.168.1.0/24",
                "dhcpd_enabled": True,
            }
        ]
    )

    assert entities == []
    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert logs[-1]["event"] == "ip_range_skipped"
    assert logs[-1]["reason"] == "dhcp_range_missing"


def test_build_ip_range_entities_skips_invalid_unifi_dhcp_range(capsys):
    assert (
        build_ip_range_entities(
            [
                {
                    "_id": "network1",
                    "name": "Default",
                    "ip_subnet": "192.168.1.0/24",
                    "dhcpd_enabled": True,
                    "dhcpd_start": "192.168.1.254",
                    "dhcpd_stop": "192.168.1.6",
                }
            ]
        )
        == []
    )

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert logs[-1]["event"] == "ip_range_skipped"
    assert logs[-1]["reason"] == "dhcp_range_order_invalid"


def test_build_ip_range_entities_skips_unifi_dhcp_range_outside_prefix(capsys):
    assert (
        build_ip_range_entities(
            [
                {
                    "_id": "network1",
                    "name": "Default",
                    "ip_subnet": "192.168.1.0/24",
                    "dhcpd_enabled": True,
                    "dhcpd_start": "192.168.2.10",
                    "dhcpd_stop": "192.168.2.20",
                }
            ]
        )
        == []
    )

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert logs[-1]["event"] == "ip_range_skipped"
    assert logs[-1]["reason"] == "dhcp_range_outside_prefix"


def test_build_vpn_entities_adds_tunnel_and_remote_prefixes():
    entities = build_vpn_entities(
        [
            {
                "_id": "vpn1",
                "name": "Office S2S",
                "type": "ipsec",
                "enabled": True,
                "remote_ip": "203.0.113.10",
                "remote_subnets": ["10.50.0.0/24", {"subnet": "10.60.0.0/24"}],
                "_unifi_endpoint": "/api/s/default/rest/vpn",
            }
        ]
    )

    fields = [entity_fields(entity)[-1] for entity in entities]
    assert fields == ["tunnel_group", "tunnel", "prefix", "prefix"]
    assert entities[0].tunnel_group.name == "UniFi VPN"
    assert entities[1].tunnel.name == "Office S2S"
    assert entities[1].tunnel.encapsulation == "ipsec-tunnel"
    assert [entity.prefix.prefix for entity in entities[2:]] == ["10.50.0.0/24", "10.60.0.0/24"]


def test_collect_vpn_configs_merges_detailed_networks_with_official_servers(monkeypatch):
    site_id = "88f7af54-98f8-306a-a1c7-c9349722b1f6"

    def fake_optional(_api_key, path, params=None):
        if path == "/integration/v1/sites":
            return [{"id": site_id, "internalReference": "default", "name": "Default"}]
        if path == f"/integration/v1/sites/{site_id}/vpn/servers":
            return [
                {"id": "official-openvpn", "name": "OpenVPN Server", "type": "OPENVPN", "enabled": True},
                {"id": "official-l2tp", "name": "L2TP Server", "type": "L2TP", "enabled": True},
                {"id": "official-wireguard", "name": "WireGuard Server 1", "type": "WIREGUARD", "enabled": True},
            ]
        return []

    monkeypatch.setattr("netbox_diode_unifi.discover.network_api_get_optional", fake_optional)
    configs = collect_vpn_configs(
        "api-key",
        "default",
        [
            {
                "_id": "legacy-openvpn",
                "name": "OpenVPN Server",
                "purpose": "remote-user-vpn",
                "vpn_type": "openvpn-server",
                "enabled": True,
                "ip_subnet": "192.168.5.1/24",
                "local_port": 1194,
                "openvpn_interface": "wan2",
            },
            {
                "_id": "legacy-l2tp",
                "name": "L2TP Server",
                "purpose": "remote-user-vpn",
                "vpn_type": "l2tp-server",
                "enabled": True,
                "ip_subnet": "192.168.6.1/24",
            },
            {
                "_id": "legacy-wireguard",
                "name": "WireGuard Server 1",
                "purpose": "remote-user-vpn",
                "vpn_type": "wireguard-server",
                "enabled": True,
                "ip_subnet": "192.168.7.1/24",
                "local_port": 51820,
                "wireguard_interface": "wan",
            },
        ],
    )

    assert len(configs) == 3
    assert {config["name"] for config in configs} == {"OpenVPN Server", "L2TP Server", "WireGuard Server 1"}
    openvpn = next(config for config in configs if config["name"] == "OpenVPN Server")
    assert openvpn["ip_subnet"] == "192.168.5.1/24"
    assert openvpn["id"] == "official-openvpn"
    assert len(openvpn["_unifi_endpoints"]) == 2


def test_build_vpn_entities_normalizes_unifi_server_types():
    entities = build_vpn_entities(
        [
            {"name": "OpenVPN Server", "vpn_type": "openvpn-server", "enabled": True},
            {"name": "L2TP Server", "vpn_type": "l2tp-server", "enabled": True},
            {"name": "WireGuard Server 1", "vpn_type": "wireguard-server", "enabled": True},
        ]
    )

    tunnels = [entity.tunnel for entity in entities if entity.HasField("tunnel")]
    assert [(tunnel.name, tunnel.encapsulation) for tunnel in tunnels] == [
        ("OpenVPN Server", "openvpn"),
        ("L2TP Server", "l2tp"),
        ("WireGuard Server 1", "wireguard"),
    ]


def test_build_vpn_entities_skips_when_unifi_has_no_vpn_configs(capsys):
    assert build_vpn_entities([]) == []

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert logs[-1]["event"] == "vpn_entities_skipped"
    assert logs[-1]["reason"] == "no_vpn_configs"


def test_prune_stale_discovery_entities_deletes_only_owned_absent_objects(monkeypatch):
    monkeypatch.setenv("NETBOX_TOKEN", "token")
    responses = {
        "/api/vpn/tunnels/?limit=1000": {
            "results": [
                {"id": 1, "name": "NNJ2", "tags": [{"slug": "diode-discovery"}, {"slug": "unifi"}]},
                {"id": 2, "name": "OpenVPN Server", "tags": [{"slug": "diode-discovery"}, {"slug": "unifi"}]},
                {"id": 3, "name": "Manual Tunnel", "tags": []},
            ]
        },
        "/api/ipam/prefixes/?limit=1000": {
            "results": [
                {"id": 10, "prefix": "192.168.1.0/24", "tags": [{"slug": "diode-discovery"}, {"slug": "unifi"}]},
                {"id": 11, "prefix": "192.168.5.0/24", "tags": [{"slug": "diode-discovery"}, {"slug": "unifi"}]},
            ]
        },
    }
    deleted_paths = []

    def fake_netbox_request(method, path, payload=None, token=None, use_branch=True):
        if method == "GET":
            return responses.get(path, {"results": []})
        if method == "DELETE":
            deleted_paths.append(path)
            return {}
        raise AssertionError((method, path))

    monkeypatch.setattr("netbox_diode_unifi.discover.netbox_request", fake_netbox_request)
    entities = [
        Entity(device=Device(name="UDM-Pro")),
        Entity(tunnel=Tunnel(name="NNJ2")),
        Entity(prefix=Prefix(prefix="192.168.1.0/24")),
    ]

    result = prune_stale_discovery_entities(entities)

    assert result == {"planned": 2, "deleted": 2, "by_resource": {"tunnels": 1, "prefixes": 1}}
    assert deleted_paths == ["/api/vpn/tunnels/2/", "/api/ipam/prefixes/11/"]


def test_prune_stale_discovery_entities_refuses_empty_device_inventory(monkeypatch):
    monkeypatch.setenv("NETBOX_TOKEN", "token")

    with pytest.raises(RuntimeError, match="discovery emitted no devices"):
        prune_stale_discovery_entities([Entity(tunnel=Tunnel(name="NNJ2"))])


def test_prune_key_normalizes_netbox_ip_range_masks():
    assert prune_key(
        "ip_ranges",
        {"start_address": "192.168.1.6/32", "end_address": "192.168.1.254/32"},
    ) == ("192.168.1.6", "192.168.1.254")


def test_build_device_entities_adds_wan_circuit_cable():
    entities = build_device_entities(
        devices=[
            {
                "_id": "dev1",
                "name": "UDM-Pro",
                "model": "UDMPRO",
                "mac": "AA:BB:CC:DD:EE:FF",
                "state": 1,
                "type": "udm",
                "port_table": [
                    {
                        "port_idx": 9,
                        "name": "WAN",
                        "ifname": "eth8",
                        "media": "GE",
                        "speed": 1000,
                        "up": True,
                    }
                ],
            }
        ],
        clients=[],
        networks=[
            {
                "_id": "wan1",
                "name": "WAN",
                "purpose": "wan",
                "external_id": "wan-primary",
                "enabled": True,
                "wan_networkgroup": "WAN",
                "wan_provider_capabilities": {
                    "download_kilobits_per_second": 1000000,
                    "upload_kilobits_per_second": 500000,
                },
            }
        ],
        wlans=[],
    )

    cable_entities = [entity for entity in entities if "cable" in entity_fields(entity)]
    assert len(cable_entities) == 1
    cable = cable_entities[0].cable
    assert cable.label == "UniFi WAN wan-primary to UDM-Pro WAN"
    assert cable.type == "cat6"
    assert cable.a_terminations[0].object_circuit_termination.circuit.cid == "wan-primary"
    assert cable.b_terminations[0].object_interface.device.name == "UDM-Pro"
    assert cable.b_terminations[0].object_interface.name == "WAN"


def test_build_device_entities_skips_wan_circuit_cable_without_discovered_wan_interface(capsys):
    entities = build_device_entities(
        devices=[
            {
                "_id": "dev1",
                "name": "UDM-Pro",
                "model": "UDMPRO",
                "mac": "AA:BB:CC:DD:EE:FF",
                "state": 1,
                "type": "udm",
                "port_table": [
                    {
                        "port_idx": 1,
                        "name": "LAN 1",
                        "ifname": "eth0",
                        "media": "GE",
                        "speed": 1000,
                        "up": True,
                    }
                ],
            }
        ],
        clients=[],
        networks=[
            {
                "_id": "wan1",
                "name": "ISP",
                "purpose": "wan",
                "external_id": "wan-primary",
                "enabled": True,
            }
        ],
        wlans=[],
    )

    assert [entity for entity in entities if "cable" in entity_fields(entity)] == []
    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    skip_log = next(log for log in logs if log["event"] == "wan_circuit_cable_skipped")
    assert skip_log["reason"] == "missing_discovered_wan_interface"
    assert skip_log["circuit"] == "wan-primary"


def test_build_device_entities_falls_back_to_first_valid_ip_without_default_network(capsys):
    entities = build_device_entities(
        devices=[
            {
                "_id": "dev1",
                "name": "Switch Test",
                "model": "USW-Test",
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "10.10.10.20",
                "ipAddress": "192.168.1.10",
                "state": 1,
                "type": "usw",
            }
        ],
        clients=[],
        networks=[],
        wlans=[],
    )

    ip_entity = next(entity for entity in entities if "ip_address" in entity_fields(entity))
    assert ip_entity.ip_address.address == "10.10.10.20/32"

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    selection_log = next(log for log in logs if log["event"] == "device_management_ip_selected")
    assert selection_log["reason"] == "first_valid"


def test_build_device_entities_skips_all_clients_when_modeling_is_disabled(capsys):
    entities = build_device_entities(
        devices=[],
        clients=[
            {
                "_id": "client1",
                "hostname": "Client A",
                "mac": "AA:BB:CC:DD:EE:FF",
            },
            {
                "_id": "client2",
                "hostname": "Client B",
                "mac": "aa-bb-cc-dd-ee-ff",
            },
        ],
        networks=[],
        wlans=[],
    )

    assert [entity for entity in entities if "mac_address" in entity_fields(entity)] == []
    assert [entity for entity in entities if "ip_address" in entity_fields(entity)] == []

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    skipped_log = next(log for log in logs if log["event"] == "client_entities_skipped")
    assert skipped_log["reason"] == "client_device_modeling_disabled"
    assert skipped_log["client_count"] == 2


def test_build_device_entities_prefers_device_mac_over_duplicate_client_mac(capsys):
    entities = build_device_entities(
        devices=[
            {
                "_id": "dev1",
                "name": "Switch Test",
                "model": "USW-Test",
                "mac": "AA:BB:CC:DD:EE:FF",
                "state": 1,
                "type": "usw",
            }
        ],
        clients=[
            {
                "_id": "client1",
                "hostname": "Client A",
                "mac": "aa:bb:cc:dd:ee:ff",
            },
        ],
        networks=[],
        wlans=[],
    )

    mac_entities = [entity for entity in entities if "mac_address" in entity_fields(entity)]
    assert len(mac_entities) == 1
    assert mac_entities[0].mac_address.description == "UniFi device MAC for Switch Test"
    assert mac_entities[0].mac_address.assigned_object_interface.name == "mgmt"
    assert mac_entities[0].mac_address.assigned_object_interface.device.name == "Switch Test"
    mgmt_entity = next(
        entity for entity in entities if "interface" in entity_fields(entity) and entity.interface.name == "mgmt"
    )
    assert mgmt_entity.interface.primary_mac_address.mac_address == "aa:bb:cc:dd:ee:ff"

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    skipped_log = next(log for log in logs if log["event"] == "client_entities_skipped")
    assert skipped_log["client_count"] == 1
