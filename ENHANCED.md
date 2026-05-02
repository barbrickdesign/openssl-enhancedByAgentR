# OpenSSL — Enhanced Repository

This repository is an enhanced fork of the upstream
[OpenSSL](https://github.com/openssl/openssl) project.  It tracks
OpenSSL **4.1.0-dev** (the in-development successor to the 3.x
stable series) and adds ready-to-use **post-quantum cryptography (PQC)**
demonstration programs as well as build-system integration for the
additional provider components listed below.

---

## Post-Quantum Cryptography Demos

OpenSSL 4.x natively implements the three NIST post-quantum cryptography
standards finalised in 2024.  The enhancements in this repository add
hands-on demonstration programs for each of them.

### ML-DSA (FIPS 204) — Module Lattice Digital Signature Algorithm

File: [`demos/signature/EVP_ML_DSA_Signature_demo.c`](demos/signature/EVP_ML_DSA_Signature_demo.c)

ML-DSA is a lattice-based digital signature scheme.  Three security
levels are available:

| Variant    | Public key | Private key | Signature | NIST security level |
|------------|-----------|-------------|-----------|---------------------|
| ML-DSA-44  | 1 312 B   | 2 528 B     | 2 420 B   | 2 (AES-128 equivalent) |
| ML-DSA-65  | 1 952 B   | 4 000 B     | 3 309 B   | 3 (AES-192 equivalent) |
| ML-DSA-87  | 2 592 B   | 4 864 B     | 4 627 B   | 5 (AES-256 equivalent) |

The demo:
- generates an **ML-DSA-65** key pair via `EVP_PKEY_Q_keygen()`,
- signs a two-part message using the **streaming**
  `EVP_PKEY_sign_message_init` / `EVP_PKEY_sign_message_update` /
  `EVP_PKEY_sign_message_final` API, and
- verifies the signature using the corresponding
  `EVP_PKEY_verify_message_*` API.

### SLH-DSA (FIPS 205) — Stateless Hash-Based Digital Signature Algorithm

File: [`demos/signature/EVP_SLH_DSA_Signature_demo.c`](demos/signature/EVP_SLH_DSA_Signature_demo.c)

SLH-DSA is a hash-based signature scheme.  Its security relies solely
on the security of its underlying hash function, giving it a
security proof that is independent of lattice hardness assumptions.
Twelve parameter sets are available, combining:

- hash function family: **SHA2** or **SHAKE**
- security level: **128 / 192 / 256** bits
- signature size optimisation: **s** (smaller, slower) or **f** (larger, faster)

The demo uses **SLH-DSA-SHA2-128s** (configurable via the `SLH_DSA_ALG`
macro) to sign and verify a message.

### ML-KEM (FIPS 203) — Module Lattice Key Encapsulation Mechanism

File: [`demos/keyexch/ml_kem.c`](demos/keyexch/ml_kem.c)

ML-KEM is a lattice-based KEM designed to replace classical
Diffie-Hellman key exchange in a post-quantum world.  Three variants are
available:

| Variant      | Public key | Private key | Ciphertext | Shared secret | NIST security level |
|--------------|-----------|-------------|-----------|--------------|---------------------|
| ML-KEM-512   |  800 B    | 1 632 B     | 768 B     | 32 B         | 1 (AES-128 equiv.) |
| ML-KEM-768   | 1 184 B   | 2 400 B     | 1 088 B   | 32 B         | 3 (AES-192 equiv.) |
| ML-KEM-1024  | 1 568 B   | 3 168 B     | 1 568 B   | 32 B         | 5 (AES-256 equiv.) |

The demo:
1. generates an **ML-KEM-768** key pair for the recipient,
2. has the sender call `EVP_PKEY_encapsulate()` with the recipient's
   public key to obtain a ciphertext and a local shared secret, and
3. has the recipient call `EVP_PKEY_decapsulate()` with their private
   key and the ciphertext to recover the same shared secret.

---

## Integrated Provider Sub-Modules

The repository includes the following sub-modules alongside the core
OpenSSL source, enabling experimentation with additional cryptographic
providers:

| Sub-module | Description |
|------------|-------------|
| [`oqs-provider`](oqs-provider/) | Open Quantum Safe provider — a wider set of PQC algorithms via liboqs |
| [`gost-engine`](gost-engine/) | GOST provider implementing Russian national cryptography standards |
| [`pkcs11-provider`](pkcs11-provider/) | PKCS#11 provider enabling hardware security modules (HSMs) |
| [`cloudflare-quiche`](cloudflare-quiche/) | Cloudflare's QUIC implementation for interoperability testing |
| [`tlsfuzzer`](tlsfuzzer/) | TLS fuzzer for protocol-level testing |
| [`wycheproof`](wycheproof/) | Google Project Wycheproof test vectors |
| [`pyca-cryptography`](pyca-cryptography/) | Python cryptography library for interoperability tests |

> **Note:** Sub-modules are registered in `.gitmodules` but are not
> automatically checked out.  Run `git submodule update --init <name>` to
> populate a specific sub-module.

---

## Building the Demos

After building OpenSSL from source (see [INSTALL.md](INSTALL.md)):

```sh
# From the repository root (after a successful build)
cd demos/signature
make
# Run all signature demos
make test

cd ../keyexch
make
# Run all key-exchange demos (including ML-KEM)
make test
```

Or, if using the OpenSSL build system directly:

```sh
./Configure
make demos
```

---

## Conformance

| Demo                         | Standard       | Algorithm   |
|------------------------------|----------------|-------------|
| `EVP_ML_DSA_Signature_demo`  | FIPS 204       | ML-DSA-65   |
| `EVP_SLH_DSA_Signature_demo` | FIPS 205       | SLH-DSA-SHA2-128s |
| `ml_kem`                     | FIPS 203       | ML-KEM-768  |

---

## Related Documentation

- [EVP_SIGNATURE-ML-DSA(7)](doc/man7/EVP_SIGNATURE-ML-DSA.pod)
- [EVP_PKEY-SLH-DSA(7)](doc/man7/EVP_PKEY-SLH-DSA.pod)
- [EVP_KEM-ML-KEM(7)](doc/man7/EVP_KEM-ML-KEM.pod)
- [EVP_PKEY-ML-KEM(7)](doc/man7/EVP_PKEY-ML-KEM.pod)
- [README-PROVIDERS.md](README-PROVIDERS.md)
- [README-QUIC.md](README-QUIC.md)
- [README-FIPS.md](README-FIPS.md)
