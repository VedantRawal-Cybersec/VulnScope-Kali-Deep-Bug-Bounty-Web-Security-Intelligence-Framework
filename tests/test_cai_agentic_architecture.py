from cai_actuator_registry import actuator_catalog
from cai_brain_cli import build_plan
from cai_sensors_cli import sensor_config


def test_actuator_catalog_has_descriptions():
    catalog = actuator_catalog()
    assert len(catalog["actuators"]) >= 10
    for item in catalog["actuators"]:
        assert item["name"]
        assert item["description"]
        assert isinstance(item["parameters"], dict)
        assert item["writes_target_data"] is False


def test_brain_plan_order():
    plan = build_plan("https://example.com", force=True)
    names = [x["actuator"] for x in plan["steps"]]
    assert names[:5] == ["dependency_status", "target_profile", "passive_recon", "input_inventory", "hypothesis_matrix"]
    assert "report" in names
    assert plan["decision"]["next_pending"] == "dependency_status"


def test_sensors_include_expected_trigger_types():
    payload = sensor_config("https://example.com")
    types = {x["type"] for x in payload["sensors"]}
    assert {"user_command", "scheduled_timer", "webhook", "file_change"}.issubset(types)
