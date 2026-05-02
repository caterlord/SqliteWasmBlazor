# PRF VFS Tamarin Model

This folder contains Tamarin models for the PRF-keyed VFS implementation in
`SqliteWasmBlazor/TypeScript/worker/vfs-prf` and its in-place conversion
wrapper.

## Files

- `vfs.spthy` models the per-slot AEAD, key registration, verification, and
  rekey primitive.
- `vfs-inplace-lifecycle.spthy` models the operational wrapper around export
  and in-place conversion: source-shape preconditions, registry lifecycle,
  temp/backup replacement, rollback, and decrypt-to-plain key purge.

## Scope

The model covers the encrypted at-rest channel:

- per-path VFS key registration,
- page AAD binding to version, path, and slot index,
- encrypted xWrite/xRead over a public attacker-controlled disk channel,
- slot-0 `verifyEncryptionKey` soundness,
- one bounded current-to-next key rotation,
- plain-to-encrypted, encrypted-to-plain, encrypted-to-encrypted, and
  plain-to-plain rekey events,
- legacy/cross-version ciphertext rejection,
- symbolic nonce freshness.

Plain VFS mode and rekey-to-plain are represented as events, not confidentiality
claims. The implementation returns plain bytes to the trusted caller in those
modes; the at-rest attacker proof is about encrypted disk material.

## Proved Lemmas

Run:

```sh
tamarin-prover --prove docs/formal/vfs-tamarin/vfs.spthy
tamarin-prover --prove docs/formal/vfs-tamarin/vfs-inplace-lifecycle.spthy
```

Expected `vfs.spthy` summary:

- `key_secrecy`
- `encrypted_slot_secrecy_unless_plain_exported`
- `encrypted_read_authenticity`
- `verify_key_match_sound`
- `rekey_encrypted_to_plain_sound`
- `rekey_encrypted_to_encrypted_sound`
- `legacy_ciphertexts_not_read_as_v1`
- `nonce_never_reused`

Expected `vfs-inplace-lifecycle.spthy` summary:

- `key_registration_requires_empty_registry`
- `export_encrypt_requires_plain_unregistered`
- `encrypt_in_place_requires_plain_unregistered`
- `export_plain_requires_encrypted_registered`
- `export_rekey_requires_encrypted_registered`
- `decrypt_in_place_requires_encrypted_registered`
- `decrypt_success_clears_registered_key`
- `decrypt_failure_clears_registered_key`
- `replacement_failure_restores_original`
- `encrypt_failure_restores_plain_original`
- `decrypt_failure_restores_encrypted_original`
- `encrypt_success_poststate`
- `decrypt_success_poststate`

All are `verified` with Tamarin 1.12.0 in the local toolchain used when this was
written.
