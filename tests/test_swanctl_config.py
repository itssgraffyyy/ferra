"""strongSwan configuration generation tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from conftest import make_config
from fera.common.errors import ConfigValidationError
from fera.dataset.schema import IpsecMode, TrafficClass
from fera.testbed.algorithms import DhGroup, EncryptionAlg, IntegrityAlg
from fera.testbed.swanctl_config import (
    connection_name,
    generate_config,
    generate_psk,
    render_secrets_file,
    render_strongswan_conf,
    render_swanctl_conf,
)

FIXED_TIME = "2026-01-01T00:00:00Z"


def test_tunnel_configuration_contains_expected_directives(topology) -> None:
    config = make_config()
    rendered = render_swanctl_conf(config, topology, "a", generated_at=FIXED_TIME)

    assert "connections {" in rendered
    assert f"\t{connection_name(config.experiment_id)} {{" in rendered
    assert "version      = 2" in rendered
    assert "local_addrs  = 10.10.10.1" in rendered
    assert "remote_addrs = 10.10.10.2" in rendered
    assert "proposals    = aes128gcm16-prfsha256-ecp256" in rendered
    assert "local_ts      = 10.20.0.0/24" in rendered
    assert "remote_ts     = 10.30.0.0/24" in rendered
    assert "mode          = tunnel" in rendered
    assert "esp_proposals = aes128gcm16-ecp256" in rendered
    assert "rekey_time    = 3600s" in rendered
    assert "life_time     = 7200s" in rendered
    assert "rand_time     = 0s" in rendered
    assert "auth = psk" in rendered
    assert "id   = endpoint-a.fera.test" in rendered


def test_transport_configuration_uses_host_selectors(topology) -> None:
    config = make_config(
        mode=IpsecMode.TRANSPORT,
        experiment_id="exp_001_transport_aes128gcm_ecp256_pfson_ipv4_icmp",
    )
    rendered = render_swanctl_conf(config, topology, "a", generated_at=FIXED_TIME)
    assert "mode          = transport" in rendered
    assert "local_ts      = 10.10.10.1/32" in rendered
    assert "remote_ts     = 10.10.10.2/32" in rendered
    assert "10.20.0.0/24" not in rendered


def test_responder_side_mirrors_the_connection(topology) -> None:
    config = make_config()
    initiator = render_swanctl_conf(config, topology, "a", generated_at=FIXED_TIME)
    responder = render_swanctl_conf(config, topology, "b", generated_at=FIXED_TIME)
    assert "local_addrs  = 10.10.10.2" in responder
    assert "remote_addrs = 10.10.10.1" in responder
    assert "local_ts      = 10.30.0.0/24" in responder
    assert "remote_ts     = 10.20.0.0/24" in responder
    assert initiator.split("connections {")[1] != responder.split("connections {")[1]


def test_cbc_configuration_uses_hmac_and_not_a_gcm_keyword(topology) -> None:
    config = make_config(
        experiment_id="exp_004_tunnel_aes256cbc_ecp384_pfson_ipv4_icmp",
        encryption=EncryptionAlg.AES256_CBC,
        integrity=IntegrityAlg.HMAC_SHA384,
        dh_group=DhGroup.ECP384,
    )
    rendered = render_swanctl_conf(config, topology, "a", generated_at=FIXED_TIME)
    assert "proposals    = aes256-sha384-ecp384" in rendered
    assert "esp_proposals = aes256-sha384-ecp384" in rendered
    esp_line = next(line for line in rendered.splitlines() if "esp_proposals" in line)
    assert "gcm" not in esp_line.lower()


def test_gcm_configuration_has_no_integrity_keyword_in_esp_proposal(topology) -> None:
    config = make_config()
    rendered = render_swanctl_conf(config, topology, "a", generated_at=FIXED_TIME)
    esp_line = next(line for line in rendered.splitlines() if "esp_proposals" in line)
    assert esp_line.strip() == "esp_proposals = aes128gcm16-ecp256"
    assert "sha" not in esp_line


def test_pfs_disabled_configuration_omits_dh_group_from_child(topology) -> None:
    config = make_config(pfs=False, experiment_id="exp_002_tunnel_aes128gcm_ecp256_pfsoff_ipv4_icmp")
    rendered = render_swanctl_conf(config, topology, "a", generated_at=FIXED_TIME)
    assert "esp_proposals = aes128gcm16\n" in rendered
    assert "proposals    = aes128gcm16-prfsha256-ecp256" in rendered


def test_generation_is_deterministic(topology) -> None:
    config = make_config(mode=IpsecMode.TRANSPORT)
    assert render_swanctl_conf(config, topology, "a", generated_at=FIXED_TIME) == render_swanctl_conf(
        config, topology, "a", generated_at=FIXED_TIME
    )


def test_secrets_are_kept_out_of_the_connection_file(topology) -> None:
    config = make_config()
    psk = generate_psk(16)
    bundle = generate_config(config, topology, psk=psk, generated_at=FIXED_TIME)

    for endpoint_text in (bundle.endpoint_a.content, bundle.endpoint_b.content):
        assert psk not in endpoint_text
        assert "secrets {" not in endpoint_text
    assert bundle.secrets_content is not None
    assert psk in bundle.secrets_content
    assert bundle.endpoint_a.to_dict()["sha256"]


def test_psk_never_appears_in_public_metadata(topology) -> None:
    config = make_config()
    psk = generate_psk(16)
    bundle = generate_config(config, topology, psk=psk, generated_at=FIXED_TIME)
    serialised = str(bundle.to_dict())
    assert psk not in serialised
    assert bundle.to_dict()["credentials_file"]["value"] == "redacted"


def test_secrets_file_lists_both_peer_identities(topology) -> None:
    config = make_config()
    rendered = render_secrets_file(config, topology, "deadbeef" * 4, generated_at=FIXED_TIME)
    assert "secrets {" in rendered
    assert "id     = endpoint-a.fera.test" in rendered
    assert "id     = endpoint-b.fera.test" in rendered
    assert rendered.count("secret = ") == 2


def test_write_produces_expected_layout(tmp_path: Path, topology) -> None:
    config = make_config()
    bundle = generate_config(config, topology, psk=generate_psk(16), generated_at=FIXED_TIME)
    written = bundle.write(tmp_path / "ipsec", secrets_dir=tmp_path / "secrets")

    config_files = [item for item in written if not item.contains_credentials]
    secret_files = [item for item in written if item.contains_credentials]
    assert {item.path.relative_to(tmp_path).as_posix() for item in config_files} == {
        "ipsec/endpoint-a/swanctl.conf",
        "ipsec/endpoint-b/swanctl.conf",
    }
    assert len(secret_files) == 1
    assert secret_files[0].path.parent.name == "secrets"
    for item in written:
        assert item.path.is_file()


def test_generate_config_without_psk_writes_no_credentials(topology) -> None:
    bundle = generate_config(make_config(), topology, psk=None, generated_at=FIXED_TIME)
    assert bundle.secrets_content is None
    assert bundle.to_dict()["credentials_file"] is None


def test_generated_psk_is_hex_and_registered_for_redaction() -> None:
    from fera.common.logging_utils import redact

    psk = generate_psk(16)
    assert len(psk) == 32
    assert all(character in "0123456789abcdef" for character in psk)
    assert psk not in redact(f"secret is {psk}")


def test_missing_ip_version_on_topology_is_rejected(topology) -> None:
    from fera.testbed.topology import Endpoint, TestbedTopology

    v4_only = TestbedTopology(
        name="v4only",
        endpoint_a=Endpoint(name="a", role="initiator", outer_ipv4="10.0.0.1/24"),
        endpoint_b=Endpoint(name="b", role="responder", outer_ipv4="10.0.0.2/24"),
    )
    config = make_config(ip_version=6, experiment_id="exp_000_tunnel_aes128gcm_ecp256_pfson_ipv6_icmp")
    with pytest.raises(ConfigValidationError):
        render_swanctl_conf(config, v4_only, "a", generated_at=FIXED_TIME)


def test_tunnel_mode_without_protected_network_is_rejected() -> None:
    from fera.testbed.topology import Endpoint, TestbedTopology

    incomplete = TestbedTopology(
        name="incomplete",
        endpoint_a=Endpoint(name="a", role="initiator", outer_ipv4="10.0.0.1/24"),
        endpoint_b=Endpoint(name="b", role="responder", outer_ipv4="10.0.0.2/24"),
    )
    with pytest.raises(ConfigValidationError):
        render_swanctl_conf(make_config(), incomplete, "a", generated_at=FIXED_TIME)


def test_strongswan_conf_sets_private_vici_socket() -> None:
    rendered = render_strongswan_conf(
        vici_socket="/run/fera-testbed/charon-a.vici",
        log_file="/tmp/charon-a.log",
    )
    assert "socket = unix:///run/fera-testbed/charon-a.vici" in rendered
    assert "path = /tmp/charon-a.log" in rendered
    assert "flush_line = yes" in rendered


def test_strongswan_conf_has_no_dotted_section_keys() -> None:
    """A section key must be a single NAME: charon rejects a dot outright.

    ``strongswan.conf(5)`` writes settings as ``charon.plugins.vici.socket``,
    which reads like the file syntax but is only documentation notation.  A
    literal dotted key makes charon abort with *syntax error, unexpected .*
    before it opens the VICI socket, so the testbed silently ends up with no
    daemon at all.  Guards the key part of every assignment and section.
    """
    rendered = render_strongswan_conf(
        vici_socket="/run/fera-testbed/charon-a.vici",
        log_file="/tmp/charon-a.log",
    )
    offenders = [
        line
        for line in rendered.splitlines()
        if not line.lstrip().startswith("#")
        and (key := line.split("=", 1)[0].split("{", 1)[0]).strip()
        and "." in key
    ]
    assert offenders == [], f"charon cannot parse {offenders}"


_CHARON = "/usr/lib/ipsec/charon"


@pytest.mark.skipif(not Path(_CHARON).is_file(), reason="strongSwan charon is not installed")
def test_strongswan_conf_is_accepted_by_charon(tmp_path: Path) -> None:
    """Let charon itself check the file: only it knows the settings grammar."""
    rendered = render_strongswan_conf(
        vici_socket=str(tmp_path / "charon-a.vici"),
        log_file=str(tmp_path / "charon-a.log"),
    )
    conf = tmp_path / "strongswan.conf"
    conf.write_text(rendered, encoding="utf-8")
    result = subprocess.run(
        [_CHARON, "--version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "STRONGSWAN_CONF": str(conf)},
    )
    output = (result.stdout or "") + (result.stderr or "")
    assert "syntax error" not in output, output
    assert "invalid config" not in output, output
    assert "abort initialization" not in output, output


def test_control_traffic_experiment_generates_configuration(topology) -> None:
    config = make_config(traffic_type=TrafficClass.CONTROL)
    rendered = render_swanctl_conf(config, topology, "a", generated_at=FIXED_TIME)
    assert "mode          = tunnel" in rendered

