# IPsec correctness rules encoded in FERA

This note records the protocol rules the code enforces, so a reviewer can check
that the dataset is not built on wrong assumptions.  Everything below is
implemented in `src/fera/testbed/algorithms.py`, `src/fera/testbed/swanctl_config.py`
and validated by `tests/test_algorithms.py` / `tests/test_swanctl_config.py`.

## 1. AES-GCM is AEAD — no separate integrity transform

`aes128gcm16`/`aes256gcm16` authenticate the payload themselves.  A separate
HMAC for ESP is *not* a hardening option, it is a different (and here invalid)
configuration, so:

* `EncryptionAlg.AES128_GCM` / `AES256_GCM` require `integrity: aead`
  (`"none"`/`"aead"`/`"gcm"` are accepted aliases);
* any other value raises `UNSUPPORTED_ALGORITHM_COMBINATION`;
* the generated **ESP** proposal for GCM therefore contains no integrity
  keyword: `esp_proposals = aes128gcm16-ecp256`;
* the matrix coverage check includes the invariant *"AES-GCM never paired with
  a separate HMAC"*, computed from the generated experiments.

## 2. AES-CBC needs integrity

`aes128`/`aes256` are AES-CBC without integrity, so the schema refuses them
unless an HMAC is configured (`hmac_sha256`, `hmac_sha384`, `hmac_sha512`) and
requires the same rule for every CBC experiment in the matrix.

## 3. IKE_SA parameters ≠ CHILD_SA parameters

They are separate objects in the generated configuration and in the ground
truth:

| | IKE_SA (`proposals`) | CHILD_SA/ESP (`esp_proposals`) |
|---|---|---|
| GCM example | `aes128gcm16-prfsha256-ecp256` | `aes128gcm16-ecp256` |
| CBC example | `aes256-sha384-ecp384` | `aes256-sha384-ecp384` |
| DH group | always present (needed for IKE) | present **iff** PFS is requested |
| PRF | needed for AEAD (named) / derived from the integrity algorithm for CBC | not applicable (ESP has no PRF) |

`TransformSet` stores them separately (`ike_proposal`, `esp_proposal`) and
`tests/test_algorithms.py::test_pfs_disabled_removes_dh_group_from_esp_proposal_only`
pins the difference.

## 4. IKE SA lifetime vs CHILD_SA lifetime

`ike_sa_lifetime_s` → IKE `rekey_time`; `child_sa_lifetime_s` → CHILD
`rekey_time`; the CHILD hard `life_time` is derived (`rekey_time + 3600s`) so a
rekey can complete before expiry.  `rand_time` is pinned to `0s` for both SAs so
that a capture window shows a deterministic rekey schedule.  Reauthentication is
disabled (`reauth_time = 0s`), which is the IKEv2 default.

## 5. PFS semantics

strongSwan expresses PFS purely through the presence of a DH group in the
CHILD_SA proposal:

* `pfs: true`  → `esp_proposals = <enc>[-<integ>]-<dh>` (e.g. `aes128gcm16-ecp256`)
* `pfs: false` → `esp_proposals = <enc>[-<integ>]` (e.g. `aes128gcm16`)

A `pfs_dh_group` together with `pfs: false` is rejected as self-contradictory
instead of silently dropping the group.  The ground truth records
`esp_proposal_contains_dh_group`, `configured_pfs` and a human readable
`pfs_semantics` string.

## 6. Configured vs observed, and what a capture can prove

Passive capture cannot prove which algorithms were negotiated, so ground truth
never claims it:

* `configured_*` = what the experiment asked for,
* `local_endpoint_reported_*` = what the endpoint's own `swanctl --list-sas`
  reported after the SA came up.  This is runtime evidence from the endpoint,
  explicitly attributed — not a passive-observation claim.

The capture sanity check (`fera.capture.sanity`) only asserts what is
*observable*: that IKE (UDP 500/4500) and ESP (IP protocol 50) appear in the
capture and that the expected IP version is present.

## 7. No fabricated algorithm support

* Proposal keywords are the documented strongSwan ones (`aes128gcm16`,
  `aes256`, `sha256/sha384/sha512`, `modp2048/modp3072/ecp256/ecp384/...`), see
  <https://docs.strongswan.org/docs/latest/config/proposals.html>.
* Groups flagged `verify_locally` (X25519) are marked as such in metadata and
  the matrix note; if the installed strongSwan rejects the keyword, the run
  fails loudly with `IPSEC_CONFIG_APPLY_FAILED`/`IPSEC_INITIATION_FAILED`
  instead of pretending success.
* Deprecated algorithms (SHA-1, MODP-768/1024, ECP-192) are accepted by
  strongSwan but are not part of FERA's vocabulary — there is deliberately no
  way to configure them silently.

## 8. Honest traffic labels

`email_like`, `voip_like`, `video_like` and `messaging_like` are synthetic
analogues; ground truth stores `traffic_label_basis` accordingly, and the
traffic registry has no mapping for brand names (mapping "whatsapp" to a
synthetic generator would be a false label).

## 9. Passive analysis limits

Nothing in this stage infers "security strength" from a capture.  Statistical
feature extraction and scoring belong to later prompts and will consume
`ground_truth.json` as the reference, never overwrite it.
