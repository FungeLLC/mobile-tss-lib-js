// tss-lib/common/types.ts

import BN from 'bn.js';
import { ec as EC } from 'elliptic';
import { PartyID } from './PartyID';
import { TssError } from './TssError';

export interface RandomSource {
	randomBytes(size: number): Buffer;
}

export interface CurveParams {
	n: BN;        // Order of the curve
	g: EC.KeyPair; // Generator point
	curve: EC;    // Elliptic curve instance
	p: BN;        // Field characteristic
}

export interface PaillierPublicKey {
	N: BN;           // Modulus
	NSquare(): BN;   // N^2
	gamma(): BN;     // N + 1
}

export interface PaillierPrivateKey {
	publicKey: PaillierPublicKey;
	lambdaN: BN;     // lcm(p-1, q-1)
	phiN: BN;        // (p-1)(q-1)
	P: BN;           // Prime factor
	Q: BN;           // Prime factor
}

export interface ProofParams {
	iterations: number;
	hashLength: number;
	primeBits: number;
}

export interface KeygenConfig {
	partyCount: number;
	threshold: number;
	curve: CurveParams;
	randomSource: RandomSource;
	proofParams: ProofParams;
}


export interface BaseParty {
	start(party: any, taskName: string): TssError | null;
	update(party: any, msg: ParsedMessage, taskName: string): [boolean, TssError | null];
	parseWireMessage(wireBytes: Uint8Array, from: PartyID, isBroadcast: boolean): ParsedMessage | TssError;
	validateMessage(msg: ParsedMessage): [boolean, TssError | null];
	toString(): string;
}

export interface ParsedMessage {
	getFrom(): PartyID;
	content(): any;
	isBroadcast: boolean;
	wireBytes: Uint8Array;
}


export interface RandomBytesProvider {
	randomBytes: (size: number) => Buffer;
}
