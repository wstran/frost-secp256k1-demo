/**
 * These constants define the elliptic curve secp256k1, widely used in cryptographic
 * applications, including Bitcoin. The curve operates over a finite field of prime
 * order P, with a base point G of order Q, specified by its coordinates GX and GY.
 */
declare const P: bigint;
declare const Q: bigint;
declare const GX: bigint;
declare const GY: bigint;

declare class Point {
    x: bigint | null;
    y: bigint | null;
    constructor(x?: bigint | null, y?: bigint | null);
    isInfinity(): boolean;
    normalize(): Point;
    static secDeserialize(hexPublicKey: string): Point;
    secSerialize(): Buffer;
    private static modularSquareRoot;
    static xonlyDeserialize(hexPublicKey: Buffer): Point;
    xonlySerialize(): Buffer;
    isZero(): boolean;
    equals(other: Point): boolean;
    negate(): Point;
    private Dbl;
    subtract(other: Point): Point;
    add(other: Point): Point;
    double(): Point;
    multiply(scalar: bigint): Point;
    toString(): string;
    modPow(base: bigint, exponent: bigint, modulus: bigint): bigint;
    static modPow(base: bigint, exponent: bigint, modulus: bigint): bigint;
    private calculateSlope;
    private calculateTangentSlope;
    private modInverse;
    static modInverse(a: bigint, m: bigint): bigint;
}
declare const G: Point;

declare class Aggregator {
    publicKey: Point;
    message: Buffer;
    nonceCommitmentPairs: [Point, Point][];
    participantIndexes: number[];
    tweakedKey: Point | null;
    tweak: bigint | null;
    constructor(publicKey: Point, message: Buffer, nonceCommitmentPairs: [Point, Point][], participantIndexes: number[], bip32Tweak?: bigint, taprootTweak?: bigint);
    static tweakKey(bip32Tweak: bigint, taprootTweak: bigint, publicKey: Point): [Point, number];
    static groupCommitment(message: Buffer, nonceCommitmentPairs: [Point, Point][], participantIndexes: number[]): Point;
    static bindingValue(index: number, message: Buffer, nonceCommitmentPairs: [Point, Point][], participantIndexes: number[]): bigint;
    static challengeHash(nonceCommitment: Point, publicKey: Point, message: Buffer): bigint;
    signingInputs(): [Buffer, [Point, Point][]];
    signature(signatureShares: bigint[]): Buffer;
    private static ComputeTweaks;
}

declare class Matrix {
    matrix: bigint[][];
    constructor(matrix: bigint[][]);
    static createVandermonde(indices: bigint[]): Matrix;
    determinant(): bigint;
    multPointMatrix(Y: Point[][]): Point[][];
    inverseMatrix(): Matrix;
    static modPow(base: bigint, exponent: bigint, modulus: bigint): bigint;
}

declare class Participant {
    private static readonly CONTEXT;
    index: number;
    threshold: number;
    participants: number;
    coefficients: bigint[] | null;
    coefficientCommitments: Point[] | null;
    proofOfKnowledge: [Point, bigint] | null;
    shares: bigint[] | null;
    aggregateShare: bigint | null;
    noncePair: [bigint, bigint] | null;
    nonceCommitmentPair: [Point, Point] | null;
    publicKey: Point | null;
    repairShares: (bigint | null)[] | null;
    aggregateRepairShare: bigint | null;
    repairShareCommitments: (Point | null)[] | null;
    groupCommitments: Point[] | null;
    repairParticipants: number[] | null;
    constructor(index: number, threshold: number, participants: number);
    initKeygen(): void;
    initRefresh(): void;
    initThresholdIncrease(newThreshold: number): void;
    private generatePolynomial;
    private generateRefreshPolynomial;
    private generateThresholdIncreasePolynomial;
    private computeProofOfKnowledge;
    private computeCoefficientCommitments;
    verifyProofOfKnowledge(proof: [Point, bigint], secretCommitment: Point, index: number): boolean;
    generateShares(): void;
    generateRepairShares(repairParticipants: number[], index: number): void;
    getRepairShare(participantIndex: number): bigint | null;
    getRepairShareCommitment(participantIndex: number, repairShareCommitments: Point[], repairParticipants?: number[]): Point | null;
    verifyAggregateRepairShare(aggregateRepairShare: bigint, repairShareCommitments: Point[][], aggregatorIndex: number, repairParticipants: number[], groupCommitments: Point[]): boolean;
    verifyRepairShare(repairShare: bigint, repairShareCommitments: Point[], repairIndex: number, dealerIndex: number): boolean;
    private evaluatePolynomial;
    _lagrangeCoefficient(participantIndexes: number[], x?: bigint, participantIndex?: bigint): bigint;
    verifyShare(share: bigint, coefficientCommitments: Point[], threshold: number): boolean;
    aggregateShares(otherShares: bigint[]): void;
    aggregateRepairShares(otherShares: bigint[]): void;
    repairShare(aggregateRepairShares: bigint[]): void;
    decrementThreshold(revealedShare: bigint, revealedShareIndex: number): void;
    increaseThreshold(otherShares: bigint[]): void;
    publicVerificationShare(): Point;
    derivePublicVerificationShare(coefficientCommitments: Point[], index: number, threshold: number): Point;
    derivePublicKey(otherSecretCommitments: Point[]): Point;
    deriveGroupCommitments(otherCoefficientCommitments: Point[][]): void;
    generateNoncePair(): void;
    sign(message: Buffer, nonceCommitmentPairs: [Point, Point][], participantIndexes: number[], bip32Tweak?: bigint, taprootTweak?: bigint): bigint;
    deriveCoefficientCommitments(publicVerificationShares: Point[], participantIndexes: number[]): Point[];
    private static modInverse;
}

declare class SingleSigner {
    private static readonly CONTEXT;
    index: number;
    threshold: number;
    participants: number;
    secret: bigint;
    coefficientCommitment: Point;
    proofOfKnowledge: [Point, bigint] | null;
    noncePair: [bigint, bigint] | null;
    nonceCommitmentPair: [Point, Point] | null;
    publicKey: Point;
    constructor(index: number, threshold: number, participants: number, secret: bigint, publicKey: Point);
    initKey(): void;
    private ComputeProofOfKnowledge;
    verifyProofOfKnowledge(proof: [Point, bigint], secretCommitment: Point, index: number): boolean;
    _lagrangeCoefficient(participantIndexes: number[], x?: bigint, participantIndex?: bigint): bigint;
    generateNoncePair(): void;
    sign(message: Buffer, nonceCommitmentPairs: [Point, Point][], participantIndexes: number[], bip32Tweak?: bigint, taprootTweak?: bigint): bigint;
    deriveCoefficientCommitments(publicVerificationShares: Point[], participantIndexes: number[]): Point[];
}

export { Aggregator, G, GX, GY, Matrix, P, Participant, Point, Q, SingleSigner };
