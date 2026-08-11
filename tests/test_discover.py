from netbox_diode_unifi.discover import (
    build_cable_entities,
    build_device_entities,
    ensure_device_types,
    ip_with_mask,
    log_event,
    netbox_interface_key,
    netbox_auth_header,
    normalize_mac,
    slugify,
)
import json
from netboxlabs.diode.sdk.ingester import Device, Interface, Manufacturer


def entity_fields(entity):
    return [field.name for field, _ in entity.ListFields()]


def test_helpers_normalize_values():
    assert slugify("UniFi Dream Machine") == "unifi-dream-machine"
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert ip_with_mask("192.168.1.10") == "192.168.1.10/32"


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


def test_ensure_device_types_uses_netbox_manufacturer_slug(monkeypatch):
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
        ("GET", "/api/dcim/device-types/?manufacturer=ubiquiti&model=UDMPRO&limit=1", None, "nbt_example.secret")
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


def test_build_device_entities_skips_duplicate_client_mac_addresses(capsys):
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

    mac_entities = [entity for entity in entities if "mac_address" in entity_fields(entity)]
    assert [entity.mac_address.mac_address for entity in mac_entities] == ["aa:bb:cc:dd:ee:ff"]

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    duplicate_log = next(log for log in logs if log["event"] == "mac_address_skipped")
    assert duplicate_log["reason"] == "duplicate"
    assert duplicate_log["mac"] == "aa:bb:cc:dd:ee:ff"
    assert duplicate_log["owner_type"] == "client"


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

    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    duplicate_log = next(log for log in logs if log["event"] == "mac_address_skipped")
    assert duplicate_log["owner_type"] == "client"
