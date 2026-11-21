import pytest

from sosya.catalog.rules import (
    HOST_LEVEL_KEYS,
    REWRITTEN_KEYS,
    SAFE_KEYS,
    RuleError,
    check_service,
    interpolate,
    stays_inside,
)

NONE: frozenset[str] = frozenset()


def test_key_sets_do_not_overlap() -> None:
    assert not set(SAFE_KEYS) & set(REWRITTEN_KEYS)
    assert not set(SAFE_KEYS) & HOST_LEVEL_KEYS
    assert not set(REWRITTEN_KEYS) & HOST_LEVEL_KEYS


@pytest.mark.parametrize(
    ("service", "reasons"),
    [
        ({"privileged": True}, ["privileged"]),
        ({"cap_add": ["NET_ADMIN", "SYS_ADMIN"]}, ["cap_add: NET_ADMIN", "cap_add: SYS_ADMIN"]),
        ({"devices": ["/dev/fuse"]}, ["devices"]),
        ({"security_opt": ["seccomp:unconfined"]}, ["security_opt: seccomp:unconfined"]),
        ({"network_mode": "host"}, ["network_mode: host"]),
        ({"pid": "host"}, ["pid: host"]),
        ({"ipc": "host"}, ["ipc: host"]),
        ({"userns_mode": "host"}, ["userns_mode: host"]),
        ({"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}, ["docker.sock mount"]),
        ({"volumes": ["/etc:/host/etc:ro"]}, ["bind mount outside the component: /etc"]),
        ({"volumes": ["~/x:/x"]}, ["bind mount outside the component: ~/x"]),
        ({"volumes": ["../secret:/x"]}, ["bind mount outside the component: ../secret"]),
        ({"volumes": ["./a/../../b:/x"]}, ["bind mount outside the component: ./a/../../b"]),
    ],
)
def test_host_level_access_is_dangerous(service: dict[str, object], reasons: list[str]) -> None:
    check = check_service(service, NONE)
    assert check.dangerous == reasons
    assert check.unsupported == []


@pytest.mark.parametrize(
    ("service", "problem"),
    [
        ({"volumes_from": ["db"]}, "key 'volumes_from'"),
        ({"volumes": ["data:/var/lib/data"]}, "named volume 'data'"),
        ({"volumes": [{"type": "bind", "source": ".", "target": "/x"}]}, "long-syntax volume"),
        ({"pid": "service:db"}, "pid: 'service:db'"),
        ({"build": "../other"}, "build context outside the component: ../other"),
    ],
)
def test_unsupported_values(service: dict[str, object], problem: str) -> None:
    unsupported = check_service(service, NONE).unsupported
    assert len(unsupported) == 1
    assert problem in unsupported[0]


def test_relative_binds_inside_the_component_are_fine() -> None:
    for source in (".", "./www", "./www/", "./a/../b", "./mnt/data1"):
        assert stays_inside(source), source


def test_interpolation_uses_the_default() -> None:
    value = {
        "user": "${AIRFLOW_UID:-50000}:${AIRFLOW_GID:-50000}",
        "environment": ["HOST=http://${CB_HOST:-localhost}:4018", "RANGE=${P-30000-30020}"],
        "healthcheck": {"test": ["CMD-SHELL", 'check "$${HOSTNAME}"']},
        "init": True,
    }
    assert interpolate(value) == {
        "user": "50000:50000",
        "environment": ["HOST=http://localhost:4018", "RANGE=30000-30020"],
        "healthcheck": {"test": ["CMD-SHELL", 'check "$${HOSTNAME}"']},
        "init": True,
    }


@pytest.mark.parametrize("text", ["${HOME}", "$HOME", "${X:?missing}", "${X:+set}", "${X:-$Y}"])
def test_interpolation_without_a_plain_default_is_refused(text: str) -> None:
    with pytest.raises(RuleError):
        interpolate(text)
