import { createHash, randomBytes } from "crypto";
import { Participant, Point as FrostPoint } from "../frost-ts/index.mjs";
import { secp256k1 } from "@noble/curves/secp256k1.js";

// ---------------- Types ----------------
interface WeierstrassPoint<T> {
  x: T;
  y: T;
  add(other: WeierstrassPoint<T>): WeierstrassPoint<T>;
  multiply(scalar: bigint): WeierstrassPoint<T>;
  toBytes(isCompressed?: boolean): Uint8Array;
}
type NonceInfo = { k: bigint; R_secp: WeierstrassPoint<bigint>; R_frost: FrostPoint };

// ---------------- Constants ----------------
const N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
); // secp256k1 order

// ---------------- Helpers ----------------
function mod(a: bigint, m = N) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function egcd(a: bigint, b: bigint) {
  let old_r = a, r = b;

  let old_s = 1n, s = 0n;

  let old_t = 0n, t = 1n;

  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
    [old_t, t] = [t, old_t - q * t];
  }

  return [old_r, old_s, old_t] as [bigint, bigint, bigint];
}
function modInv(a: bigint, m = N) {
  const [g, x] = egcd(((a % m) + m) % m, m);

  if (g !== 1n) throw new Error("not invertible");

  return mod(x, m);
}

function bigintToHex32(b: bigint) {
  let h = b.toString(16);

  if (h.length % 2) h = "0" + h;

  return h.padStart(64, "0");
}

function frostPointToCompressedHex(pt: FrostPoint) {
  const prefix = ((pt.y as bigint) % 2n === 0n) ? "02" : "03";

  return prefix + bigintToHex32(pt.x as bigint);
}
function frostPointToCompressedBytes(pt: FrostPoint) {
  return Buffer.from(frostPointToCompressedHex(pt), "hex");
}

function sha256ToBigInt(...parts: Uint8Array[]) {
  const h = createHash("sha256");

  for (const p of parts) h.update(p);

  return BigInt("0x" + h.digest("hex"));
}

function lagrangeAtZero(i: number, S: number[]) {
  let num = 1n, den = 1n;

  for (const j of S) {
    if (j === i) continue;

    num = mod(num * BigInt(-j));

    den = mod(den * (BigInt(i) - BigInt(j)));
  }

  return mod(num * modInv(den));
}

// ---------------- PoK helpers (Schnorr non-interactive) ----------------
// We'll create per-coefficient proofs. Each proof: { R_bytes, z }
// Challenge c = H(commitment_bytes || R_bytes || participant_index || coeff_index)
function schnorrProveScalar(secret: bigint, commitmentBytes: Uint8Array, pid: number, coeffIndex: number) {
  const r = mod(BigInt("0x" + randomBytes(32).toString("hex")));

  const R_point = secp256k1.Point.BASE.multiply(r);

  const R_bytes = R_point.toBytes(true);

  // include pid and coeffIndex into challenge to bind proof
  const c = mod(sha256ToBigInt(commitmentBytes, R_bytes, Buffer.from(String(pid)), Buffer.from(String(coeffIndex))));

  const z = mod(r + c * secret);

  return { R_bytes, z, c };
}
function schnorrVerifyScalar(commitmentBytes: Uint8Array, proof: { R_bytes: Uint8Array, z: bigint, c?: bigint }, pid: number, coeffIndex: number) {
  const C = secp256k1.Point.fromHex(Buffer.from(commitmentBytes).toString("hex"));

  const R = secp256k1.Point.fromHex(Buffer.from(proof.R_bytes).toString("hex"));

  const c = proof.c ?? mod(sha256ToBigInt(commitmentBytes, proof.R_bytes, Buffer.from(String(pid)), Buffer.from(String(coeffIndex))));

  const left = secp256k1.Point.BASE.multiply(proof.z);

  const right = R.add(C.multiply(c));

  return left.x === right.x && left.y === right.y;
}

// ---------------- DKG ----------------
// Create participants
const participants = [
  new Participant(1, 3, 4),
  new Participant(2, 3, 4),
  new Participant(3, 3, 4),
  new Participant(4, 3, 4),
];

// Each participant generates polynomial commitments and shares
participants.forEach(p => {
  p.initKeygen();
  p.generateShares();
});

// === PoK: each participant proves knowledge of each coefficient they committed ===
// We'll build proofs per participant per coefficient, then verify them (simulated broadcast).
type CoeffProof = { R_bytes: Uint8Array; z: bigint; c?: bigint };
const allProofs: Record<number, CoeffProof[]> = {};

// Produce proofs locally (participant does this before broadcasting commitments)
participants.forEach(p => {
  if (!p.coefficientCommitments) throw new Error("missing commitments");
  const proofs: CoeffProof[] = [];
  // library exposes p.coefficients[] as bigint array (the secret coefficients)
  const coeffs: bigint[] = (p as any).coefficients;

  if (!coeffs || coeffs.length === 0) throw new Error("coefficients missing in participant");

  for (let k = 0; k < coeffs.length; k++) {
    const a_k = coeffs[k]; // secret coefficient a_{i,k}

    const Ck = p.coefficientCommitments[k]; // FrostPoint

    const Ck_bytes = frostPointToCompressedBytes(Ck);

    const proof = schnorrProveScalar(a_k, Ck_bytes, p.index, k);

    proofs.push({ R_bytes: proof.R_bytes, z: proof.z, c: proof.c });
  }

  allProofs[p.index] = proofs;
});

// Simulated verification by peers (each peer verifies every participant's proofs)
participants.forEach(p => {
  const proofs = allProofs[p.index];
  console.log(`Verifying proofs for participant ${p.index} ...`);
  for (let k = 0; k < proofs.length; k++) {
    const Ck = p.coefficientCommitments![k];
    const ok = schnorrVerifyScalar(frostPointToCompressedBytes(Ck), proofs[k], p.index, k);
    console.log(`coeff ${k} PoK ok?`, ok);
    if (!ok) throw new Error(`PoK failed for participant ${p.index} coeff ${k}`);
  }
});
console.log("All PoK checks passed.");

// ---------------- Distribute & verify shares using commitments ----------------
// In production, shares are sent over private channels. Here we simulate and verify each incoming share.
function verifyShareFromSender(sender: Participant, receiverIndex: number, share: bigint) {
  // Check: g^share ?= product_k (C_{sender,k})^{receiverIndex^k}
  // Compute left = G^share
  const left = secp256k1.Point.BASE.multiply(share);

  // Compute right = sum_k C_{k} * (receiverIndex^k)
  let right: typeof secp256k1.Point.BASE | null = null;
  const Cvec = sender.coefficientCommitments!;
  for (let k = 0; k < Cvec.length; k++) {
    const Ck = Cvec[k];
    const Ck_secp = secp256k1.Point.fromHex(frostPointToCompressedHex(Ck));
    // scalar = receiverIndex^k
    const scalar = BigInt(receiverIndex) ** BigInt(k);
    const term = Ck_secp.multiply(mod(scalar));
    right = right ? right.add(term) : term;
  }

  if (!right) throw new Error("no right side computed");

  // compare
  return left.x === right.x && left.y === right.y;
}

// simulate sending shares and verification before accepting
participants.forEach(receiver => {
  for (const sender of participants) {
    if (sender.index === receiver.index) continue;
    const share = sender.shares![receiver.index - 1]; // what sender created for receiver
    const ok = verifyShareFromSender(sender, receiver.index, share);
    console.log(`Share from ${sender.index} -> ${receiver.index} valid?`, ok);
    if (!ok) throw new Error(`Invalid share from ${sender.index} to ${receiver.index}`);
  }
});

// Now call aggregateShares on each receiver (as in your flow)
participants.forEach(receiver => {
  const incoming = participants
    .filter(s => s.index !== receiver.index)
    .map(s => s.shares![receiver.index - 1]);
  receiver.aggregateShares(incoming);
});

// fallback: compute local combined shares (should equal receiver.aggregateShare or equivalent)
const localShareById: Record<number, bigint> = {};
participants.forEach(sender => {
  sender.shares!.forEach((share, idx) => {
    const rec = idx + 1;
    if (!localShareById[rec]) localShareById[rec] = 0n;
    localShareById[rec] += share;
  });
});
console.log("Local combined shares:", localShareById);

// ---------------- compute group public key ----------------
function computeGroupPublicKey(parts: Participant[]) {
  let gp: FrostPoint | null = null;
  for (const p of parts) {
    const c0 = p.coefficientCommitments![0];
    const fp = new FrostPoint(c0.x, c0.y);
    gp = gp ? gp.add(fp) : fp;
  }
  return gp!;
}
const groupPK = computeGroupPublicKey(participants);
console.log("Group PK (compressed):", frostPointToCompressedHex(groupPK));

// ---------------- Signing (t-of-n) ----------------
// message
const message = Buffer.from("hello frost");

// choose signers (we'll use all for demo; threshold is 3 so any >=3 works)
const signers = [1, 2, 3]; // pick first 3

// nonces
const nonces: Record<number, NonceInfo> = {};
for (const id of signers) {
  let k: bigint;
  do {
    k = mod(BigInt("0x" + randomBytes(32).toString("hex")));
  } while (k === 0n);
  const R_secp = secp256k1.Point.BASE.multiply(k);
  const R_bytes = R_secp.toBytes(true);
  const R_fromHex = secp256k1.Point.fromHex(Buffer.from(R_bytes).toString("hex"));
  const R_frost = new FrostPoint(R_fromHex.x, R_fromHex.y);
  nonces[id] = { k, R_secp, R_frost };
}

// aggregate R
let R_agg_secp: WeierstrassPoint<bigint> | null = null;
for (const id of signers) {
  R_agg_secp = R_agg_secp ? R_agg_secp.add(nonces[id].R_secp) : nonces[id].R_secp;
}
if (!R_agg_secp) throw new Error("no nonces");
const R_agg_bytes = R_agg_secp.toBytes(true);
console.log("R_agg (compressed):", Buffer.from(R_agg_bytes).toString("hex"));

// challenge e = H(R || PK || msg)
const pk_bytes = frostPointToCompressedBytes(groupPK);
const e = mod(sha256ToBigInt(R_agg_bytes, pk_bytes, message));

// partial sigs: s_i = k_i + e * lambda_i * d_i
const partialSigs: Record<number, bigint> = {};
for (const id of signers) {
  const signer = participants[id - 1];
  const d_i: bigint = (signer as any).aggregateShare ?? localShareById[id];
  if (d_i === undefined) throw new Error("no local share for " + id);
  const lambda = lagrangeAtZero(id, signers);
  partialSigs[id] = mod(nonces[id].k + e * lambda * d_i);
}
console.log("Partial sigs:", Object.fromEntries(Object.entries(partialSigs).map(([i, v]) => [i, v.toString(16)])));

// aggregate S
const S_agg = mod(Object.values(partialSigs).reduce((a, b) => a + b, 0n));

// verify signature: S*G == R + e*PK
const left = secp256k1.Point.BASE.multiply(S_agg);
const groupPK_secp = secp256k1.Point.fromHex(Buffer.from(pk_bytes).toString("hex"));
const right = R_agg_secp.add(groupPK_secp.multiply(e));
console.log("Signature valid?", left.x === right.x && left.y === right.y);
