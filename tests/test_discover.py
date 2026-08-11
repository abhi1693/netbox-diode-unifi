from netbox_diode_unifi.discover import (
    build_cable_entities,
    build_device_entities,
    ensure_device_types,
    ip_with_mask,
    netbox_interface_key,
    netbox_auth_header,
    normalize_mac,
    slugify,
)
from netboxlabs.diode.sdk.ingester import Device, Interface, Manufacturer


def entity_fields(entity):
    return [field.name for field, _ in entity.ListFields()]


def test_helpers_normalize_values():
    assert slugify("UniFi Dream Machine") == "unifi-dream-machine"
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert ip_with_mask("192.168.1.10") == "192.168.1.10/32"


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
