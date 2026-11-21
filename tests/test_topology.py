from factories import services_of

from sosya import topology
from sosya.spec import parse_range


def spec(hosts: list[dict[str, object]], internet: bool = True):
    return parse_range(
        {
            "apiVersion": "sosya/v1",
            "name": "lab",
            "networks": ["dmz"],
            "hosts": hosts,
            "attacker": {"networks": ["dmz"], "internet": internet},
        }
    )


WP = {"name": "wp", "component": "vulhub/wordpress/pwnscriptum", "networks": ["dmz"]}


def test_primary_takes_the_host_name_and_siblings_stay_private() -> None:
    plan = topology.build(spec([WP]), services_of)
    wp, db, attacker = plan.containers
    assert (wp.key, wp.primary, wp.segments, wp.private) == ("wp", True, ("dmz",), "wp-net")
    assert wp.private_aliases == ("wordpress",)
    assert (db.key, db.primary, db.segments, db.private) == ("wp-mysql", False, (), "wp-net")
    assert db.private_aliases == ("mysql",)
    assert attacker.segments == ("dmz", "egress")
    assert plan.key_map("wp") == {"wordpress": "wp", "mysql": "wp-mysql"}
    assert topology.name_problems(plan) == []


def test_service_chooses_the_dns_name_and_every_published_service_is_exposed() -> None:
    definitions = {
        "front": {"image": "a", "ports": ["80"]},
        "admin": {"image": "b", "ports": ["8080"]},
        "db": {"image": "c"},
    }
    host = {"name": "app", "component": "vulhub/x/y", "networks": ["dmz"], "service": "admin"}
    plan = topology.build(spec([host]), lambda _: definitions)
    keys = {c.original: (c.key, c.segments) for c in plan.containers if c.host == "app"}
    assert keys == {
        "front": ("app-front", ("dmz",)),
        "admin": ("app", ("dmz",)),
        "db": ("app-db", ()),
    }


def test_single_service_component_has_no_private_network() -> None:
    host = {"name": "web", "component": "vulhub/struts2/s2-045", "networks": ["dmz"]}
    plan = topology.build(spec([host], internet=False), services_of)
    assert plan.private_networks == ()
    assert plan.containers[0].private is None
    assert plan.containers[-1].segments == ("dmz",)


def test_link_aliases_become_private_aliases() -> None:
    definitions = {
        "app": {"image": "a", "ports": ["80"], "links": ["database:db", "cache"]},
        "database": {"image": "b"},
        "cache": {"image": "c"},
    }
    host = {"name": "app", "component": "vulhub/x/y", "networks": ["dmz"]}
    plan = topology.build(spec([host]), lambda _: definitions)
    aliases = {c.original: c.private_aliases for c in plan.containers if c.host == "app"}
    assert aliases == {"app": ("app",), "database": ("database", "db"), "cache": ("cache",)}
