from cits_validator.rules.export import export_rule_catalog


def test_catalog_lists_all_rules_with_ids():
    catalog = export_rule_catalog()
    ids = {r["rule_id"] for r in catalog["rules"]}
    assert {"R01", "R02", "R03", "R04", "R05", "R06"} <= ids
    assert all({"rule_id", "name", "description", "metadata"} <= set(r) for r in catalog["rules"])
