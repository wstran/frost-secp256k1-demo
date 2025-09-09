// src/constants.ts
var P = 2n ** 256n - 2n ** 32n - 977n;
var Q = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);
var GX = BigInt(
  "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
);
var GY = BigInt(
  "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
);

// src/point.ts
function mod(a, b) {
  return (a % b + b) % b;
}
var Point = class _Point {
  x;
  y;
  constructor(x = null, y = null) {
    this.x = x;
    this.y = y;
  }
  isInfinity() {
    return this.x === null || this.y === null;
  }
  normalize() {
    if (this.isInfinity()) {
      return new _Point(null, null);
    }
    if (this.y > P - this.y) {
      return new _Point(this.x, (P - this.y) % P);
    }
    return new _Point(this.x, this.y);
  }
  static secDeserialize(hexPublicKey) {
    try {
      const hexBytes = Buffer.from(hexPublicKey, "hex");
      if (hexBytes.length !== 33) {
        throw new Error(
          "Input must be exactly 33 bytes long for SEC 1 compressed format."
        );
      }
      const isEven = hexBytes[0] === 2;
      const xBytes = hexBytes.slice(1);
      const x = BigInt(`0x${xBytes.toString("hex")}`);
      const ySquared = (x ** 3n + 7n) % P;
      let y = this.modPow(ySquared, (P + 1n) / 4n, P);
      if (y % 2n === 0n) {
        y = isEven ? y : (P - y) % P;
      } else {
        y = isEven ? (P - y) % P : y;
      }
      return new _Point(x, y);
    } catch (e) {
      throw new Error(
        "Invalid hex input or unable to compute point from x-coordinate."
      );
    }
  }
  secSerialize() {
    if (this.x === null || this.y === null) {
      throw new Error("Cannot serialize the point at infinity.");
    }
    const prefix = this.y % 2n === 0n ? Buffer.from([2]) : Buffer.from([3]);
    const xBytes = Buffer.alloc(32);
    let x = this.x;
    for (let i = 31; i >= 0; i--) {
      xBytes[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return Buffer.concat([prefix, xBytes]);
  }
  static modularSquareRoot(a, p) {
    if (p % 4n === 3n) {
      const r = this.modPow(a, (p + 1n) / 4n, p);
      if (r * r % p === a) return r;
      return null;
    }
    throw new Error(
      "Modular square root algorithm not implemented for this prime"
    );
  }
  static xonlyDeserialize(hexPublicKey) {
    if (hexPublicKey.length !== 32) {
      throw new Error(
        `Invalid hex length: expected 64, got ${hexPublicKey.length}`
      );
    }
    try {
      const x = BigInt(`0x${hexPublicKey.toString("hex")}`);
      const ySquared = (x * x * x + 7n) % P;
      let y = this.modularSquareRoot(ySquared, P);
      if (y === null) {
        throw new Error("Unable to compute valid y-coordinate");
      }
      if (y % 2n !== 0n) {
        y = (P - y) % P;
      }
      return new _Point(x, y);
    } catch (error) {
      throw new Error(
        "Invalid hex input or unable to compute point from x-coordinate"
      );
    }
  }
  xonlySerialize() {
    if (this.x === null || this.y === null) {
      throw new Error("Cannot serialize point at infinity");
    }
    const buffer = Buffer.alloc(32);
    const xHex = this.x.toString(16).padStart(64, "0");
    buffer.write(xHex, 0, "hex");
    return buffer;
  }
  isZero() {
    return this.x === null || this.y === null;
  }
  equals(other) {
    if (!(other instanceof _Point)) {
      return false;
    }
    return this.x === other.x && this.y === other.y;
  }
  negate() {
    if (this.x === null || this.y === null) {
      return this;
    }
    return new _Point(this.x, P - this.y);
  }
  Dbl() {
    if (this.x === null || this.y === null || this.y === 0n) {
      return new _Point();
    }
    const x = this.x;
    const y = this.y;
    const s = 3n * x * x * _Point.modInverse(2n * y, P) % P;
    const sumX = (s * s - 2n * x) % P;
    const sumY = (s * (x - sumX) - y) % P;
    return new _Point(sumX, sumY);
  }
  subtract(other) {
    return this.add(other.negate());
  }
  add(other) {
    if (!(other instanceof _Point)) {
      throw new Error("The other object must be an instance of Point");
    }
    if (this.equals(other)) {
      return this.double();
    }
    if (this.isInfinity()) {
      return new _Point(other.x, other.y);
    }
    if (other.isInfinity()) {
      return new _Point(this.x, this.y);
    }
    if (this.x === other.x && this.y !== other.y) {
      return new _Point(null, null);
    }
    const s = mod(
      (other.y - this.y) * this.modInverse(other.x - this.x, P),
      P
    );
    const sumX = mod(s * s - this.x - other.x, P);
    const sumY = mod(s * (this.x - sumX) - this.y, P);
    return new _Point(sumX, sumY);
  }
  double() {
    if (this.isInfinity() || this.y === 0n) {
      return new _Point(null, null);
    }
    const x = this.x;
    const y = this.y;
    const s = mod(3n * x * x * this.modInverse(2n * y, P), P);
    const sumX = mod(s * s - 2n * x, P);
    const sumY = mod(s * (x - sumX) - y, P);
    return new _Point(sumX, sumY);
  }
  multiply(scalar) {
    scalar = mod(scalar, Q);
    if (typeof scalar !== "bigint") {
      throw new Error("The scalar must be a bigint");
    }
    let p = new _Point(this.x, this.y);
    let r = new _Point(null, null);
    let i = 1n;
    while (i <= scalar) {
      if (i & scalar) {
        r = r.add(p);
      }
      p = p.double();
      i <<= 1n;
    }
    return r;
  }
  toString() {
    if (this.isZero()) {
      return "0";
    }
    return `X: 0x${this.x.toString(16)}
Y: 0x${this.y.toString(16)}`;
  }
  modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = result * base % modulus;
      }
      exponent = exponent >> 1n;
      base = base * base % modulus;
    }
    return result;
  }
  static modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = result * base % modulus;
      }
      exponent = exponent >> 1n;
      base = base * base % modulus;
    }
    return result;
  }
  calculateSlope(other) {
    const dx = (other.x - this.x + P) % P;
    const dy = (other.y - this.y + P) % P;
    return dy * this.modInverse(dx, P) % P;
  }
  calculateTangentSlope() {
    const numerator = 3n * this.x * this.x % P;
    const denominator = 2n * this.y % P;
    return numerator * this.modInverse(denominator, P) % P;
  }
  modInverse(a, m) {
    let [oldR, r] = [mod(a, m), m];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
      const quotient = oldR / r;
      [oldR, r] = [r, oldR - quotient * r];
      [oldS, s] = [s, oldS - quotient * s];
    }
    if (oldR > 1n) {
      throw new Error("Modular inverse does not exist");
    }
    return mod(oldS, m);
  }
  static modInverse(a, m) {
    let [oldR, r] = [mod(a, m), m];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
      const quotient = oldR / r;
      [oldR, r] = [r, oldR - quotient * r];
      [oldS, s] = [s, oldS - quotient * s];
    }
    if (oldR > 1n) {
      throw new Error("Modular inverse does not exist");
    }
    return mod(oldS, m);
  }
};
var G = new Point(GX, GY);

// src/aggregator.ts
import * as crypto from "crypto";
function sha256(data) {
  if (data !== void 0) {
    return crypto.createHash("sha256").update(data);
  }
  return crypto.createHash("sha256");
}
var Aggregator = class _Aggregator {
  publicKey;
  message;
  nonceCommitmentPairs;
  participantIndexes;
  tweakedKey;
  tweak;
  constructor(publicKey, message, nonceCommitmentPairs, participantIndexes, bip32Tweak, taprootTweak) {
    this.publicKey = publicKey;
    this.message = message;
    this.nonceCommitmentPairs = nonceCommitmentPairs;
    this.participantIndexes = participantIndexes;
    this.tweakedKey = null;
    this.tweak = null;
    if (bip32Tweak === void 0 !== (taprootTweak === void 0)) {
      throw new Error(
        "Both bip32Tweak and taprootTweak must be provided together, or neither."
      );
    }
    if (bip32Tweak !== void 0 && taprootTweak !== void 0) {
      const [tweakedKey, tweak] = _Aggregator.ComputeTweaks(
        bip32Tweak,
        taprootTweak,
        publicKey
      );
      this.tweakedKey = tweakedKey;
      this.tweak = tweak;
    }
  }
  static tweakKey(bip32Tweak, taprootTweak, publicKey) {
    const [tweakedKey, _, p] = _Aggregator.ComputeTweaks(
      bip32Tweak,
      taprootTweak,
      publicKey
    );
    return [tweakedKey, Number(p)];
  }
  static groupCommitment(message, nonceCommitmentPairs, participantIndexes) {
    let groupCommitment = new Point(null, null);
    for (const index of participantIndexes) {
      if (index < 1 || index > nonceCommitmentPairs.length) {
        throw new Error(`Participant index ${index} is out of range.`);
      }
      const bindingValue = _Aggregator.bindingValue(
        index,
        message,
        nonceCommitmentPairs,
        participantIndexes
      );
      const [firstCommitment, secondCommitment] = nonceCommitmentPairs[index - 1];
      const partialCommitment = firstCommitment.add(
        secondCommitment.multiply(bindingValue)
      );
      groupCommitment = groupCommitment.add(partialCommitment);
    }
    if (groupCommitment.isInfinity()) {
      throw new Error("Resulting group commitment is the point at infinity");
    }
    return groupCommitment;
  }
  static bindingValue(index, message, nonceCommitmentPairs, participantIndexes) {
    if (index < 1) {
      throw new Error("Participant index must start from 1.");
    }
    const bindingValue = sha256();
    const indexByte = Buffer.alloc(1);
    indexByte.writeUInt8(index);
    const nonceCommitmentPairsBytes = [];
    for (const idx of participantIndexes) {
      if (idx < 1 || idx > nonceCommitmentPairs.length) {
        throw new Error(`Index ${idx} is out of range for nonce commitments.`);
      }
      const participantPair = nonceCommitmentPairs[idx - 1];
      const participantPairBytes = Buffer.concat(
        participantPair.map((commitment) => commitment.secSerialize())
      );
      nonceCommitmentPairsBytes.push(participantPairBytes);
    }
    bindingValue.update(indexByte);
    bindingValue.update(message);
    bindingValue.update(Buffer.concat(nonceCommitmentPairsBytes));
    const bindingValueBytes = bindingValue.digest();
    return BigInt(`0x${bindingValueBytes.toString("hex")}`) % Q;
  }
  static challengeHash(nonceCommitment, publicKey, message) {
    const tagHash = crypto.createHash("sha256").update("BIP0340/challenge").digest();
    const challengeHash = crypto.createHash("sha256").update(tagHash).update(tagHash).update(nonceCommitment.xonlySerialize()).update(publicKey.xonlySerialize()).update(message).digest();
    return BigInt(`0x${challengeHash.toString("hex")}`) % Q;
  }
  signingInputs() {
    return [this.message, this.nonceCommitmentPairs];
  }
  signature(signatureShares) {
    const groupCommitment = _Aggregator.groupCommitment(
      this.message,
      this.nonceCommitmentPairs,
      this.participantIndexes
    );
    let z = signatureShares.reduce((sum, share) => (sum + share) % Q, 0n);
    if (z < 0n) {
      z = (z + Q) % Q;
    }
    if (this.tweak !== null && this.tweakedKey !== null) {
      const challengeHash = _Aggregator.challengeHash(
        groupCommitment,
        this.tweakedKey,
        this.message
      );
      z = (z + challengeHash * this.tweak) % Q;
    }
    const nonceCommitmentBuffer = groupCommitment.xonlySerialize();
    const zBuffer = Buffer.alloc(32);
    const zHex = z.toString(16).padStart(64, "0");
    zBuffer.write(zHex, 0, "hex");
    return Buffer.concat([nonceCommitmentBuffer, zBuffer]);
  }
  static ComputeTweaks(bip32Tweak, taprootTweak, publicKey) {
    const bip32Key = publicKey.add(G.multiply(bip32Tweak));
    if (bip32Key.y === null) {
      throw new Error("Invalid public key.");
    }
    const isBip32KeyOdd = bip32Key.y % 2n !== 0n;
    const adjustedBip32Key = isBip32KeyOdd ? bip32Key.negate() : bip32Key;
    const bip32Parity = isBip32KeyOdd ? 1 : 0;
    const adjustedBip32Tweak = isBip32KeyOdd ? -bip32Tweak : bip32Tweak;
    const aggregateKey = adjustedBip32Key.add(G.multiply(taprootTweak));
    if (aggregateKey.y === null) {
      throw new Error("Invalid public key.");
    }
    const aggregateTweak = (adjustedBip32Tweak + taprootTweak) % Q;
    const adjustedAggregateTweak = aggregateKey.y % 2n !== 0n ? (-aggregateTweak + Q) % Q : aggregateTweak;
    return [aggregateKey, adjustedAggregateTweak, bip32Parity];
  }
};

// src/matrix.ts
var Matrix = class _Matrix {
  matrix;
  constructor(matrix) {
    this.matrix = matrix;
  }
  static createVandermonde(indices) {
    const n = indices.length;
    const matrix = indices.map(
      (x) => Array.from({ length: n }, (_, i) => x ** BigInt(i) % Q)
    );
    return new _Matrix(matrix);
  }
  determinant() {
    if (this.matrix.length === 1) {
      return this.matrix[0][0] % Q;
    }
    if (this.matrix.length === 2) {
      return (this.matrix[0][0] * this.matrix[1][1] - this.matrix[0][1] * this.matrix[1][0]) % Q;
    }
    let det = 0n;
    for (let c = 0; c < this.matrix.length; c++) {
      const minor = new _Matrix(
        this.matrix.slice(1).map((row) => [...row.slice(0, c), ...row.slice(c + 1)])
      );
      det += (-1n) ** BigInt(c) * this.matrix[0][c] * minor.determinant() % Q;
      det %= Q;
    }
    return det;
  }
  multPointMatrix(Y) {
    const result = [];
    for (const aRow of this.matrix) {
      const rowResult = [];
      for (let j = 0; j < Y[0].length; j++) {
        let sumPoint = new Point();
        for (let k = 0; k < aRow.length; k++) {
          const point = Y[k][j];
          sumPoint = sumPoint.add(point.multiply(aRow[k]));
        }
        rowResult.push(sumPoint);
      }
      result.push(rowResult);
    }
    return result;
  }
  inverseMatrix() {
    const n = this.matrix.length;
    const adj = Array.from({ length: n }, () => Array(n).fill(0n));
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        const minor = new _Matrix(
          this.matrix.filter((_, x) => x !== i).map((row) => row.filter((_, y) => y !== j))
        );
        adj[j][i] = (-1n) ** BigInt(i + j) * minor.determinant() % Q;
      }
    }
    const det = this.determinant();
    const detInv = _Matrix.modPow(det, Q - 2n, Q);
    for (let row = 0; row < n; row++) {
      for (let col = 0; col < n; col++) {
        adj[row][col] = adj[row][col] * detInv % Q;
      }
    }
    return new _Matrix(adj);
  }
  static modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = result * base % modulus;
      }
      exponent = exponent >> 1n;
      base = base * base % modulus;
    }
    return result;
  }
};

// src/participant.ts
import * as crypto2 from "crypto";
function pow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = result * base % modulus;
    }
    exponent = exponent >> 1n;
    base = base * base % modulus;
  }
  return result;
}
var Participant = class _Participant {
  static CONTEXT = Buffer.from("FROST-BIP340");
  index;
  threshold;
  participants;
  coefficients = null;
  coefficientCommitments = null;
  proofOfKnowledge = null;
  shares = null;
  aggregateShare = null;
  noncePair = null;
  nonceCommitmentPair = null;
  publicKey = null;
  repairShares = null;
  aggregateRepairShare = null;
  repairShareCommitments = null;
  groupCommitments = null;
  repairParticipants = null;
  constructor(index, threshold, participants) {
    if (!Number.isInteger(index) || !Number.isInteger(threshold) || !Number.isInteger(participants)) {
      throw new Error(
        "All arguments (index, threshold, participants) must be integers."
      );
    }
    this.index = index;
    this.threshold = threshold;
    this.participants = participants;
  }
  initKeygen() {
    this.generatePolynomial();
    this.computeProofOfKnowledge();
    this.computeCoefficientCommitments();
  }
  initRefresh() {
    this.generateRefreshPolynomial();
    this.computeCoefficientCommitments();
  }
  initThresholdIncrease(newThreshold) {
    if (!Number.isInteger(newThreshold)) {
      throw new Error("New threshold must be an integer.");
    }
    if (newThreshold <= this.threshold) {
      throw new Error(
        "New threshold must be greater than the current threshold."
      );
    }
    this.generateThresholdIncreasePolynomial(newThreshold);
    this.computeProofOfKnowledge();
    this.computeCoefficientCommitments();
    this.threshold = newThreshold;
  }
  generatePolynomial() {
    this.coefficients = Array.from({ length: this.threshold }, (_, i) => {
      let randomValue = BigInt(`0x${crypto2.randomBytes(32).toString("hex")}`);
      return randomValue % Q;
    });
  }
  generateRefreshPolynomial() {
    this.coefficients = [
      0n,
      ...Array.from(
        { length: this.threshold - 1 },
        () => BigInt(Math.floor(Math.random() * Number(Q)))
      )
    ];
  }
  generateThresholdIncreasePolynomial(newThreshold) {
    this.coefficients = Array.from(
      { length: newThreshold - 1 },
      () => BigInt(Math.floor(Math.random() * Number(Q)))
    );
  }
  computeProofOfKnowledge() {
    if (!this.coefficients || this.coefficients.length === 0) {
      throw new Error("Polynomial coefficients must be initialized.");
    }
    const nonce = BigInt(`0x${crypto2.randomBytes(32).toString("hex")}`) % Q;
    const nonceCommitment = G.multiply(nonce);
    const indexByte = Buffer.alloc(1);
    indexByte.writeUInt8(this.index);
    const contextBytes = _Participant.CONTEXT;
    const secret = this.coefficients[0];
    const secretCommitment = G.multiply(secret);
    const secretCommitmentBytes = secretCommitment.secSerialize();
    const nonceCommitmentBytes = nonceCommitment.secSerialize();
    const challengeHash = crypto2.createHash("sha256");
    challengeHash.update(indexByte);
    challengeHash.update(contextBytes);
    challengeHash.update(secretCommitmentBytes);
    challengeHash.update(nonceCommitmentBytes);
    const challengeHashBytes = challengeHash.digest();
    const challengeHashInt = BigInt(`0x${challengeHashBytes.toString("hex")}`);
    const s = (nonce + secret * challengeHashInt) % Q;
    this.proofOfKnowledge = [nonceCommitment, s];
  }
  computeCoefficientCommitments() {
    if (!this.coefficients) {
      throw new Error("Polynomial coefficients must be initialized.");
    }
    this.coefficientCommitments = this.coefficients.map(
      (coefficient) => G.multiply(coefficient)
    );
  }
  verifyProofOfKnowledge(proof, secretCommitment, index) {
    if (proof.length !== 2) {
      throw new Error(
        "Proof must be a tuple containing exactly two elements (nonce commitment and s)."
      );
    }
    const [nonceCommitment, s] = proof;
    if (!(nonceCommitment instanceof Point) || typeof s !== "bigint") {
      throw new Error("Proof must contain a Point and a bigint.");
    }
    const indexByte = Buffer.alloc(1);
    indexByte.writeUInt8(index);
    const contextBytes = _Participant.CONTEXT;
    const secretCommitmentBytes = secretCommitment.secSerialize();
    const nonceCommitmentBytes = nonceCommitment.secSerialize();
    const challengeInput = Buffer.concat([
      indexByte,
      contextBytes,
      secretCommitmentBytes,
      nonceCommitmentBytes
    ]);
    const challengeHash = crypto2.createHash("sha256").update(challengeInput).digest();
    const challengeHashInt = BigInt(`0x${challengeHash.toString("hex")}`);
    const expectedNonceCommitment = G.multiply(s).add(
      secretCommitment.multiply(Q - challengeHashInt)
    );
    return nonceCommitment.equals(expectedNonceCommitment);
  }
  generateShares() {
    if (!this.coefficients) {
      throw new Error(
        "Polynomial coefficients must be initialized before generating shares."
      );
    }
    this.shares = Array.from(
      { length: this.participants },
      (_, i) => this.evaluatePolynomial(BigInt(i + 1))
    );
  }
  generateRepairShares(repairParticipants, index) {
    if (this.aggregateShare === null) {
      throw new Error("Aggregate share has not been initialized.");
    }
    const lagrangeCoefficient = this._lagrangeCoefficient(
      repairParticipants,
      0n,
      BigInt(index)
    );
    const randomShares = Array.from(
      { length: this.threshold - 1 },
      () => BigInt(Math.floor(Math.random() * Number(Q)))
    );
    const finalShare = (lagrangeCoefficient * this.aggregateShare - randomShares.reduce((a, b) => a + b, 0n)) % Q;
    this.repairShares = [...randomShares, finalShare];
    this.repairShareCommitments = this.repairShares.map(
      (share) => share !== null ? G.multiply(share) : null
    );
    this.repairParticipants = [...repairParticipants, this.index].sort(
      (a, b) => a - b
    );
  }
  getRepairShare(participantIndex) {
    if (!this.repairParticipants || !this.repairShares) {
      throw new Error("Repair shares have not been initialized.");
    }
    if (!this.repairParticipants.includes(participantIndex)) {
      throw new Error("Participant index does not match the initial set.");
    }
    const mappedIndex = this.repairParticipants.indexOf(participantIndex);
    return this.repairShares[mappedIndex];
  }
  getRepairShareCommitment(participantIndex, repairShareCommitments, repairParticipants) {
    if (!repairParticipants) {
      if (!this.repairParticipants) {
        throw new Error("Repair participants must be initialized or provided.");
      }
      repairParticipants = this.repairParticipants;
    }
    if (!repairParticipants.includes(participantIndex)) {
      throw new Error("Participant index does not match the initial set.");
    }
    const mappedIndex = repairParticipants.indexOf(participantIndex);
    return repairShareCommitments[mappedIndex];
  }
  verifyAggregateRepairShare(aggregateRepairShare, repairShareCommitments, aggregatorIndex, repairParticipants, groupCommitments) {
    if (repairShareCommitments.length !== this.threshold) {
      throw new Error(
        "The number of repair share commitments must match the threshold."
      );
    }
    for (let i = 0; i < repairParticipants.length; i++) {
      const dealerIndex = repairParticipants[i];
      const commitments = repairShareCommitments[i];
      const lagrangeCoefficient = this._lagrangeCoefficient(
        repairParticipants,
        BigInt(this.index),
        BigInt(dealerIndex)
      );
      const dealerPublicShare = this.derivePublicVerificationShare(
        groupCommitments,
        dealerIndex,
        this.threshold
      );
      if (!dealerPublicShare.multiply(lagrangeCoefficient).equals(
        commitments.reduce(
          (sum, commitment) => sum.add(commitment),
          new Point()
        )
      )) {
        return false;
      }
    }
    const aggregateRepairShareCommitment = repairShareCommitments.reduce(
      (sum, commitments) => sum.add(
        this.getRepairShareCommitment(
          aggregatorIndex,
          commitments,
          repairParticipants
        ) || new Point()
      ),
      new Point()
    );
    return G.multiply(aggregateRepairShare).equals(
      aggregateRepairShareCommitment
    );
  }
  verifyRepairShare(repairShare, repairShareCommitments, repairIndex, dealerIndex) {
    if (!this.groupCommitments) {
      throw new Error("Group commitments must be initialized.");
    }
    if (!this.repairParticipants) {
      throw new Error("Repair participants must be initialized.");
    }
    if (!G.multiply(repairShare).equals(
      this.getRepairShareCommitment(this.index, repairShareCommitments) || new Point()
    )) {
      return false;
    }
    if (repairShareCommitments.length !== this.threshold) {
      throw new Error(
        "The number of repair share commitments must match the threshold."
      );
    }
    const lagrangeCoefficient = this._lagrangeCoefficient(
      this.repairParticipants,
      BigInt(repairIndex),
      BigInt(dealerIndex)
    );
    const dealerPublicShare = this.derivePublicVerificationShare(
      this.groupCommitments,
      dealerIndex,
      this.threshold
    );
    return dealerPublicShare.multiply(lagrangeCoefficient).equals(
      repairShareCommitments.reduce(
        (sum, commitment) => sum.add(commitment),
        new Point()
      )
    );
  }
  evaluatePolynomial(x) {
    if (typeof x !== "bigint") {
      throw new Error("The value of x must be a bigint.");
    }
    if (!this.coefficients || this.coefficients.length === 0) {
      throw new Error("Polynomial coefficients must be initialized.");
    }
    let y = 0n;
    for (let i = this.coefficients.length - 1; i >= 0; i--) {
      y = (y * x + this.coefficients[i]) % Q;
    }
    return y;
  }
  _lagrangeCoefficient(participantIndexes, x = 0n, participantIndex) {
    if (new Set(participantIndexes).size !== participantIndexes.length) {
      throw new Error("Participant indexes must be unique.");
    }
    if (participantIndex === void 0) {
      participantIndex = BigInt(this.index);
    }
    let numerator = 1n;
    let denominator = 1n;
    for (const index of participantIndexes) {
      if (BigInt(index) === participantIndex) {
        continue;
      }
      numerator = numerator * (x - BigInt(index));
      denominator = denominator * (participantIndex - BigInt(index));
    }
    return numerator * pow(denominator, Q - 2n, Q) % Q;
  }
  verifyShare(share, coefficientCommitments, threshold) {
    if (coefficientCommitments.length !== threshold) {
      throw new Error(
        "The number of coefficient commitments must match the threshold."
      );
    }
    const expectedShare = this.derivePublicVerificationShare(
      coefficientCommitments,
      this.index,
      threshold
    );
    return G.multiply(share).equals(expectedShare);
  }
  aggregateShares(otherShares) {
    if (!this.shares) {
      throw new Error("Participant's shares have not been initialized.");
    }
    if (this.index - 1 < 0 || this.index - 1 >= this.shares.length) {
      throw new Error("Participant index is out of range.");
    }
    if (otherShares.length !== this.participants - 1) {
      throw new Error(
        `Expected exactly ${this.participants - 1} other shares, received ${otherShares.length}.`
      );
    }
    let aggregateShare = this.shares[this.index - 1];
    for (const otherShare of otherShares) {
      aggregateShare = (aggregateShare + otherShare) % Q;
    }
    if (this.aggregateShare !== null) {
      this.aggregateShare = (this.aggregateShare + aggregateShare) % Q;
    } else {
      this.aggregateShare = aggregateShare;
    }
  }
  aggregateRepairShares(otherShares) {
    if (!this.repairShares) {
      throw new Error("Participant's repair shares have not been initialized.");
    }
    if (otherShares.length !== this.threshold - 1) {
      throw new Error(
        `Expected exactly ${this.threshold - 1} other shares, received ${otherShares.length}.`
      );
    }
    let aggregateRepairShare = this.getRepairShare(this.index);
    if (aggregateRepairShare === null) {
      throw new Error("Repair share for this participant is null.");
    }
    for (const otherShare of otherShares) {
      aggregateRepairShare = (aggregateRepairShare + otherShare) % Q;
    }
    this.aggregateRepairShare = aggregateRepairShare;
  }
  repairShare(aggregateRepairShares) {
    if (this.aggregateShare !== null) {
      throw new Error("Participant's share has not been lost");
    }
    if (aggregateRepairShares.length !== this.threshold) {
      throw new Error(
        `Expected exactly ${this.threshold} aggregate repair shares, received ${aggregateRepairShares.length}.`
      );
    }
    this.aggregateShare = aggregateRepairShares.reduce(
      (a, b) => (a + b) % Q,
      0n
    );
  }
  decrementThreshold(revealedShare, revealedShareIndex) {
    if (this.aggregateShare === null) {
      throw new Error("Participant's share has not been initialized.");
    }
    if (this.groupCommitments === null) {
      throw new Error("Group commitments have not been initialized.");
    }
    const numerator = this.aggregateShare - revealedShare;
    const denominator = BigInt(this.index - revealedShareIndex);
    const quotient = numerator * _Participant.modInverse(denominator, Q) % Q;
    this.aggregateShare = (revealedShare - BigInt(revealedShareIndex) * quotient) % Q;
    this.threshold -= 1;
    const publicVerificationShares = [];
    const indexes = [];
    const FJ = G.multiply(revealedShare);
    for (let index = 1; index <= this.threshold; index++) {
      const FI = this.derivePublicVerificationShare(
        this.groupCommitments,
        index,
        this.threshold + 1
      );
      const inverseIJ = _Participant.modInverse(
        BigInt(index - revealedShareIndex),
        Q
      );
      const FpI = FJ.subtract(
        FI.subtract(FJ).multiply(BigInt(revealedShareIndex) * inverseIJ)
      );
      publicVerificationShares.push(FpI);
      indexes.push(index);
    }
    const groupCommitments = this.deriveCoefficientCommitments(
      publicVerificationShares,
      indexes
    );
    this.groupCommitments = groupCommitments;
  }
  increaseThreshold(otherShares) {
    if (!this.shares) {
      throw new Error("Participant's shares have not been initialized.");
    }
    if (!this.aggregateShare) {
      throw new Error(
        "Participant's aggregate share has not been initialized."
      );
    }
    const aggregateShare = (this.shares[this.index - 1] + otherShares.reduce((a, b) => a + b, 0n)) % Q;
    this.aggregateShare = (this.aggregateShare + aggregateShare * BigInt(this.index)) % Q;
  }
  publicVerificationShare() {
    if (this.aggregateShare === null) {
      throw new Error("Aggregate share has not been initialized.");
    }
    return G.multiply(this.aggregateShare);
  }
  derivePublicVerificationShare(coefficientCommitments, index, threshold) {
    if (coefficientCommitments.length !== threshold) {
      throw new Error(
        "The number of coefficient commitments must match the threshold."
      );
    }
    let expectedYCommitment = new Point();
    for (let k = 0; k < coefficientCommitments.length; k++) {
      expectedYCommitment = expectedYCommitment.add(
        coefficientCommitments[k].multiply(BigInt(index) ** BigInt(k) % Q)
      );
    }
    return expectedYCommitment;
  }
  derivePublicKey(otherSecretCommitments) {
    if (!this.coefficientCommitments || this.coefficientCommitments.length === 0) {
      throw new Error(
        "Coefficient commitments have not been initialized or are empty."
      );
    }
    let publicKey = this.coefficientCommitments[0];
    for (const otherSecretCommitment of otherSecretCommitments) {
      publicKey = publicKey.add(otherSecretCommitment);
    }
    this.publicKey = publicKey;
    return publicKey;
  }
  deriveGroupCommitments(otherCoefficientCommitments) {
    if (!this.coefficientCommitments || this.coefficientCommitments.length === 0) {
      throw new Error(
        "Coefficient commitments have not been initialized or are empty."
      );
    }
    const groupCommitments = otherCoefficientCommitments[0].map(
      (_, i) => otherCoefficientCommitments.reduce((sum, commitments) => sum.add(commitments[i]), new Point()).add(this.coefficientCommitments[i])
    );
    if (this.groupCommitments !== null) {
      this.groupCommitments = this.groupCommitments.map(
        (commitment, i) => commitment.add(groupCommitments[i])
      );
    } else {
      this.groupCommitments = groupCommitments;
    }
  }
  generateNoncePair() {
    const noncePair = [
      BigInt(Math.floor(Math.random() * Number(Q))),
      BigInt(Math.floor(Math.random() * Number(Q)))
    ];
    const nonceCommitmentPair = [
      G.multiply(noncePair[0]),
      G.multiply(noncePair[1])
    ];
    this.noncePair = noncePair;
    this.nonceCommitmentPair = nonceCommitmentPair;
  }
  sign(message, nonceCommitmentPairs, participantIndexes, bip32Tweak, taprootTweak) {
    if (!this.noncePair) {
      throw new Error("Nonce pair has not been initialized.");
    }
    if (!this.publicKey) {
      throw new Error("Public key has not been initialized.");
    }
    if (!this.publicKey.x || !this.publicKey.y) {
      throw new Error("Public key is the point at infinity.");
    }
    if (this.aggregateShare === null) {
      throw new Error("Aggregate share has not been initialized.");
    }
    const groupCommitment = Aggregator.groupCommitment(
      message,
      nonceCommitmentPairs,
      participantIndexes
    );
    if (groupCommitment.isInfinity()) {
      throw new Error("Group commitment is the point at infinity.");
    }
    let publicKey = this.publicKey;
    let parity = 0;
    if (bip32Tweak !== void 0 && taprootTweak !== void 0) {
      [publicKey, parity] = Aggregator.tweakKey(
        bip32Tweak,
        taprootTweak,
        this.publicKey
      );
    }
    const challengeHash = Aggregator.challengeHash(
      groupCommitment,
      publicKey,
      message
    );
    let [firstNonce, secondNonce] = this.noncePair;
    if (groupCommitment.y % 2n !== 0n) {
      firstNonce = Q - firstNonce;
      secondNonce = Q - secondNonce;
    }
    const bindingValue = Aggregator.bindingValue(
      this.index,
      message,
      nonceCommitmentPairs,
      participantIndexes
    );
    const lagrangeCoefficient = this._lagrangeCoefficient(participantIndexes);
    let aggregateShare = this.aggregateShare;
    if (publicKey.y === null) {
      throw new Error("Public key is the point at infinity.");
    }
    if (publicKey.y % 2n !== BigInt(parity)) {
      aggregateShare = Q - aggregateShare;
    }
    return (firstNonce + secondNonce * bindingValue + lagrangeCoefficient * aggregateShare * challengeHash) % Q;
  }
  deriveCoefficientCommitments(publicVerificationShares, participantIndexes) {
    if (publicVerificationShares.length !== participantIndexes.length) {
      throw new Error(
        "The number of public verification shares must match the number of participant indexes."
      );
    }
    const A = Matrix.createVandermonde(
      participantIndexes.map((i) => BigInt(i))
    );
    const AInv = A.inverseMatrix();
    const Y = publicVerificationShares.map((share) => [share]);
    const coefficients = AInv.multPointMatrix(Y);
    return coefficients.map((coeff) => coeff[0]);
  }
  static modInverse(a, m) {
    let [oldR, r] = [a, m];
    let [oldS, s] = [1n, 0n];
    let [oldT, t] = [0n, 1n];
    while (r !== 0n) {
      const quotient = oldR / r;
      [oldR, r] = [r, oldR - quotient * r];
      [oldS, s] = [s, oldS - quotient * s];
      [oldT, t] = [t, oldT - quotient * t];
    }
    if (oldR > 1n) {
      throw new Error("Modular inverse does not exist");
    }
    if (oldS < 0n) {
      oldS += m;
    }
    return oldS;
  }
};

// src/singleSigner.ts
import * as crypto3 from "crypto";
function pow2(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = result * base % modulus;
    }
    exponent = exponent >> 1n;
    base = base * base % modulus;
  }
  return result;
}
var SingleSigner = class _SingleSigner {
  static CONTEXT = Buffer.from("FROST-BIP340");
  index;
  threshold;
  participants;
  secret;
  coefficientCommitment;
  proofOfKnowledge = null;
  noncePair = null;
  nonceCommitmentPair = null;
  publicKey;
  constructor(index, threshold, participants, secret, publicKey) {
    if (!Number.isInteger(index) || !Number.isInteger(threshold) || !Number.isInteger(participants)) {
      throw new Error(
        "All arguments (index, threshold, participants) must be integers."
      );
    }
    this.index = index;
    this.threshold = threshold;
    this.participants = participants;
    this.secret = secret;
    this.coefficientCommitment = G.multiply(secret);
    this.publicKey = publicKey;
  }
  initKey() {
    this.ComputeProofOfKnowledge();
  }
  ComputeProofOfKnowledge() {
    if (!this.secret) {
      throw new Error("Polynomial coefficient must be initialized.");
    }
    let nonce = BigInt(`0x${crypto3.randomBytes(32).toString("hex")}`) % Q;
    const nonceCommitment = G.multiply(nonce);
    const indexByte = Buffer.alloc(1);
    indexByte.writeUInt8(this.index);
    const contextBytes = _SingleSigner.CONTEXT;
    const secret = this.secret;
    const secretCommitment = G.multiply(secret);
    const secretCommitmentBytes = secretCommitment.secSerialize();
    const nonceCommitmentBytes = nonceCommitment.secSerialize();
    const challengeHash = crypto3.createHash("sha256");
    challengeHash.update(indexByte);
    challengeHash.update(contextBytes);
    challengeHash.update(secretCommitmentBytes);
    challengeHash.update(nonceCommitmentBytes);
    const challengeHashBytes = challengeHash.digest();
    const challengeHashInt = BigInt(`0x${challengeHashBytes.toString("hex")}`);
    const s = (nonce + secret * challengeHashInt) % Q;
    this.proofOfKnowledge = [nonceCommitment, s];
  }
  verifyProofOfKnowledge(proof, secretCommitment, index) {
    if (proof.length !== 2) {
      throw new Error(
        "Proof must be a tuple containing exactly two elements (nonce commitment and s)."
      );
    }
    const [nonceCommitment, s] = proof;
    if (!(nonceCommitment instanceof Point) || typeof s !== "bigint") {
      throw new Error("Proof must contain a Point and a bigint.");
    }
    const indexByte = Buffer.alloc(1);
    indexByte.writeUInt8(index);
    const contextBytes = _SingleSigner.CONTEXT;
    const secretCommitmentBytes = secretCommitment.secSerialize();
    const nonceCommitmentBytes = nonceCommitment.secSerialize();
    const challengeInput = Buffer.concat([
      indexByte,
      contextBytes,
      secretCommitmentBytes,
      nonceCommitmentBytes
    ]);
    const challengeHash = crypto3.createHash("sha256").update(challengeInput).digest();
    const challengeHashInt = BigInt(`0x${challengeHash.toString("hex")}`);
    const expectedNonceCommitment = G.multiply(s).add(
      secretCommitment.multiply(Q - challengeHashInt)
    );
    return nonceCommitment.equals(expectedNonceCommitment);
  }
  _lagrangeCoefficient(participantIndexes, x = 0n, participantIndex) {
    if (new Set(participantIndexes).size !== participantIndexes.length) {
      throw new Error("Participant indexes must be unique.");
    }
    if (participantIndex === void 0) {
      participantIndex = BigInt(this.index);
    }
    let numerator = 1n;
    let denominator = 1n;
    for (const index of participantIndexes) {
      if (BigInt(index) === participantIndex) {
        continue;
      }
      numerator = numerator * (x - BigInt(index));
      denominator = denominator * (participantIndex - BigInt(index));
    }
    return numerator * pow2(denominator, Q - 2n, Q) % Q;
  }
  generateNoncePair() {
    const noncePair = [
      BigInt(Math.floor(Math.random() * Number(Q))),
      BigInt(Math.floor(Math.random() * Number(Q)))
    ];
    const nonceCommitmentPair = [
      G.multiply(noncePair[0]),
      G.multiply(noncePair[1])
    ];
    this.noncePair = noncePair;
    this.nonceCommitmentPair = nonceCommitmentPair;
  }
  sign(message, nonceCommitmentPairs, participantIndexes, bip32Tweak, taprootTweak) {
    if (!this.noncePair) {
      throw new Error("Nonce pair has not been initialized.");
    }
    if (!this.publicKey) {
      throw new Error("Public key has not been initialized.");
    }
    if (!this.publicKey.x || !this.publicKey.y) {
      throw new Error("Public key is the point at infinity.");
    }
    const groupCommitment = Aggregator.groupCommitment(
      message,
      nonceCommitmentPairs,
      participantIndexes
    );
    if (groupCommitment.isInfinity()) {
      throw new Error("Group commitment is the point at infinity.");
    }
    let publicKey = this.publicKey;
    let parity = 0;
    if (bip32Tweak !== void 0 && taprootTweak !== void 0) {
      [publicKey, parity] = Aggregator.tweakKey(
        bip32Tweak,
        taprootTweak,
        this.publicKey
      );
    }
    const challengeHash = Aggregator.challengeHash(
      groupCommitment,
      publicKey,
      message
    );
    let [firstNonce, secondNonce] = this.noncePair;
    if (groupCommitment.y % 2n !== 0n) {
      firstNonce = Q - firstNonce;
      secondNonce = Q - secondNonce;
    }
    const bindingValue = Aggregator.bindingValue(
      this.index,
      message,
      nonceCommitmentPairs,
      participantIndexes
    );
    const lagrangeCoefficient = this._lagrangeCoefficient(participantIndexes);
    let secret = this.secret;
    if (publicKey.y === null) {
      throw new Error("Public key is the point at infinity.");
    }
    if (publicKey.y % 2n !== BigInt(parity)) {
      secret = Q - secret;
    }
    return (firstNonce + secondNonce * bindingValue + lagrangeCoefficient * secret * challengeHash) % Q;
  }
  deriveCoefficientCommitments(publicVerificationShares, participantIndexes) {
    if (publicVerificationShares.length !== participantIndexes.length) {
      throw new Error(
        "The number of public verification shares must match the number of participant indexes."
      );
    }
    const A = Matrix.createVandermonde(
      participantIndexes.map((i) => BigInt(i))
    );
    const AInv = A.inverseMatrix();
    const Y = publicVerificationShares.map((share) => [share]);
    const coefficients = AInv.multPointMatrix(Y);
    return coefficients.map((coeff) => coeff[0]);
  }
};
export {
  Aggregator,
  G,
  GX,
  GY,
  Matrix,
  P,
  Participant,
  Point,
  Q,
  SingleSigner
};
