# Experiment Matrix & Coverage

This document outlines the rationale, algorithm combinations, and matrix generation rules
used in FERA Stage 1.

---

## Design Objectives

1. **Broad Cryptographic Coverage**: Cover mainstream modern ciphers (AES-GCM, ChaCha20-Poly1305, AES-CBC), integrity algorithms (HMAC-SHA2-256, HMAC-SHA2-384, HMAC-SHA2-512), and Diffie-Hellman groups (ECP 256/384/521, Curve25519, MODP 2048/3072/4096).
2. **Dual-Stack IP Support**: Test scenarios under both IPv4 and IPv6 outer encapsulation.
3. **PFS Variations**: Evaluate tunnels with Perfect Forward Secrecy enabled (DH re-negotiated on ESP child SAs) and disabled.
4. **Diverse Traffic Classes**: Pair cryptographic combinations with multiple application traffic profiles (Control, ICMP, Web, VoIP, Video, Messaging, Email).
5. **Deterministic Matrix Generation**: Ensure matrix generation produces identical experiment IDs and configurations given the same parameters.

---

## Matrix Generation Rules

Matrix entries are produced via `fera.dataset.matrix.build_matrix()` and verified by `scripts/check_matrix_coverage.py`.

### Cryptographic Combinations

| Cipher Family | Algorithm | Integrity / Auth | Allowed DH Groups |
|---------------|-----------|------------------|-------------------|
| AEAD | AES-128-GCM, AES-256-GCM | Built-in AEAD (no separate HMAC) | ECP256, ECP384, MODP2048, Curve25519 |
| AEAD | ChaCha20-Poly1305 | Built-in AEAD (no separate HMAC) | ECP256, Curve25519 |
| CBC | AES-128-CBC, AES-256-CBC | SHA256, SHA384, SHA512 | MODP2048, MODP3072, ECP256, ECP384 |

### PFS Rules
* **PFS Enabled (`pfs=True`)**: ESP child SA proposals explicitly include a DH group matching or compatible with the IKE SA DH group.
* **PFS Disabled (`pfs=False`)**: ESP child SA proposals omit DH group specifications, deriving keys directly from the parent IKE SA.

---

## Verifying Matrix Coverage

To verify that all required combinations and constraints are satisfied:

```bash
python scripts/generate_experiment_matrix.py --output configs/experiments
python scripts/check_matrix_coverage.py --matrix configs/experiments
```
