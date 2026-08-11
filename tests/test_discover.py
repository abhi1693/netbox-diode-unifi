from netbox_diode_unifi.discover import (
    build_device_entities,
    ip_with_mask,
    netbox_auth_header,
    normalize_mac,
    slugify,
)


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
