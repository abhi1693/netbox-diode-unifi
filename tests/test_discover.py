from netbox_diode_unifi.discover import build_entities, ip_with_mask, normalize_mac, slugify


def entity_fields(entity):
    return [field.name for field, _ in entity.ListFields()]


def test_helpers_normalize_values():
    assert slugify("UniFi Dream Machine") == "unifi-dream-machine"
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert ip_with_mask("192.168.1.10") == "192.168.1.10/32"


def test_build_entities_assigns_device_ip_to_management_interface():
    entities = build_entities(
        sites=[{"id": "site1"}],
        devices=[
            {
                "id": "dev1",
                "name": "AP Test",
                "model": "U7-Pro",
                "macAddress": "AA:BB:CC:DD:EE:FF",
                "ipAddress": "192.168.1.10",
                "state": "ONLINE",
                "firmwareVersion": "1.0.0",
            }
        ],
        clients=[],
        networks=[],
    )

    assert [entity_fields(entity)[-1] for entity in entities] == [
        "site",
        "interface",
        "ip_address",
        "device",
    ]

    ip_entity = entities[2]
    assert ip_entity.ip_address.address == "192.168.1.10/32"
    assert ip_entity.ip_address.assigned_object_interface.name == "mgmt"
    assert ip_entity.ip_address.assigned_object_interface.device.name == "AP Test"
