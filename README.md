# FROST on secp256k1 – Threshold Schnorr Signatures (MPC Demo)

This repo is a **learning and demo implementation** of [FROST](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/), a protocol for **threshold Schnorr signatures** using the `secp256k1` curve (the same curve used by Bitcoin and Ethereum).

It shows how multiple participants can collaboratively generate a keypair and sign messages **without ever reconstructing the private key**.
The goal is to share knowledge and provide a base for further research in MPC (multi-party computation) and wallet infrastructure.

---

## ✨ Features

* Distributed Key Generation (DKG) with `t-of-n` threshold setup
* Proof of Knowledge (PoK) for each participant's contribution
* Share distribution & verification
* Aggregation of group public key
* Threshold signing with nonces, challenge, partial signatures, and aggregation
* Final verification of aggregated Schnorr signatures

---

## 🔑 Protocol Overview

This repo follows two main phases: **Key Generation** and **Signing**.

### 1. Distributed Key Generation (DKG)

* Agree on parameters: `t = threshold`, `n = participants`.
* Each participant locally generates polynomial coefficients → produces:

  * **shares** for other participants,
  * **commitments** (public coefficients),
  * and a **Proof of Knowledge (PoK)** that they know the secret behind their commitments.
* Before sending shares, each participant broadcasts their `(commitment, PoK)` to everyone.
  Other participants verify this to avoid "dusting" or fake contributions.
* Each participant then sends their **private share** (indexed) to every other participant.
  ⚠️ You never send your own share for yourself.
* Upon receiving shares, each participant verifies correctness using the sender’s commitments.
* Once all valid shares are received, each participant aggregates them → this becomes their **local secret share**.
* The group public key is derived by summing the first coefficient commitment (`c0`) from all participants.
  (Other commitments are used for verification but not directly in the final PK.)
* ✅ At this stage, no one knows the full private key, only their own share.

### 2. Threshold Signing

* Suppose we need `t-of-n` participants to sign a message.
* Steps:

  1. **Nonce generation**: Each signer creates a random nonce and computes `R = k·G`.
     All Rs are shared → aggregate to `R_agg`.
  2. **Challenge computation**:
     `e = H(R_agg, groupPublicKey, message)`
  3. **Partial signature**:
     Each signer computes `s_i = k_i + e * λ_i * share_i`
     (λ = Lagrange coefficient for interpolation at 0).
  4. **Aggregation**: Partial signatures are summed:
     `S = Σ s_i`.
  5. **Final signature**: `(R_agg, S)`.
* **Verification**:
  Check that:

  ```
  S·G == R_agg + e·groupPublicKey
  ```

  If true, the aggregated signature is valid.

---

## 📂 Project Structure

```
.
├── frost-ts/    # participant and helper classes
├── src/
│   ├── mpc-sign-clean.ts   # main demo implementation
├── package.json
└── README.md
```

---

## 🚀 Usage

### Install

```bash
npm install
```

### Run

```bash
npm run dev
```

### Example Output

* DKG with shares and PoK verification
* Computed group public key
* Threshold signing demo (`t-of-n`)
* Aggregated signature verification

---

## ⚠️ Disclaimer

* This repo is for **educational and research purposes only**.
* It is **not production-ready**. Real-world FROST requires stronger security guarantees:

  * Properly binding nonces to prevent replay / rogue attacks,
  * Zero-knowledge proofs (ZK PoK) instead of simple Schnorr PoK,
  * Robust network layer for share/nonce distribution,
  * Resistance against malicious adversaries.

---

## 📚 References

* [FROST Draft Spec](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/)
* [Noble Secp256k1](https://github.com/paulmillr/noble-curves)
* Research on MPC and threshold cryptography
