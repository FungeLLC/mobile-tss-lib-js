import BN from 'bn.js';
import { ec as EC } from 'elliptic';
import { ECPoint } from './ECPoint';
import ModInt from '../common/ModInt';
import { getRandomPositiveInt } from '../common/Random';
import crypto from 'crypto';

type RandomSource = {
	randomBytes(size: number): Buffer;
};

export class Share {
	constructor(
		public threshold: number,
		public id: BN,      // xi
		public share: BN    // Sigma i
	) { }

	public verify(ec: EC, threshold: number, vs: Vs): boolean {
		if (this.threshold !== threshold || !vs || vs.length !== threshold + 1 || !ec.n) {
			return false;
		}

		const modN = new ModInt(ec.n);
		let v = vs[0];
		let t = new BN(1);

		try {
			for (let j = 1; j <= threshold; j++) {
				// t = k_i^j
				t = modN.mul(t, this.id) as BN;
				// v = v * v_j^t
				const vjt = vs[j].scalarMult(t);
				v = v.add(vjt);
			}
			const sigmaGi = ECPoint.scalarBaseMult(ec, this.share);
			return sigmaGi.equals(v);
		} catch {
			return false;
		}
	}
}

export type Vs = ECPoint[]; // v0..vt
export type Shares = Share[];



export function Create(
	threshold: number,
	secret: BN,
	indexes: BN[],
	ec: EC,
	rand: RandomSource
): [Vs, Shares] {
	if (!secret || !indexes) {
		throw new Error("vss secret or indexes == nil");
	}
	if (threshold < 1) {
		throw new Error("vss threshold < 1");
	}

	// Check indexes
	const uniqueIndexes = new Map<string, boolean>();
	if (!ec.n) {
		throw new Error("ec.n is undefined");
	}
	for (const v of indexes) {
		const vMod = v.mod(ec.n);
		if (vMod.isZero()) {
			throw new Error("party index should not be 0");
		}
		const vModStr = vMod.toString();
		if (uniqueIndexes.has(vModStr)) {
			throw new Error(`duplicate indexes ${vModStr}`);
		}
		uniqueIndexes.set(vModStr, true);
	}

	const num = indexes.length;
	if (num < threshold) {
		throw new Error("not enough shares to satisfy the threshold");
	}

	// Generate polynomial coefficients
	const poly = samplePolynomial(ec, threshold, secret, rand);

	// Generate commitment points
	const v: Vs = poly.map(ai => ECPoint.scalarBaseMult(ec, ai));

	// Generate shares
	const shares: Shares = indexes.map(id => {
		const share = evaluatePolynomial(ec, threshold, poly, id);
		return new Share(threshold, id, share);
	});

	return [v, shares];
}

function samplePolynomial(ec: EC, threshold: number, secret: BN, rand: RandomSource): BN[] {
	const v = new Array(threshold + 1);
	v[0] = secret;
	for (let i = 1; i <= threshold; i++) {
		if(!ec.n) throw new Error('ec.n is undefined');
		const randInt = getRandomPositiveInt(BigInt(ec.n.toString()));
		if (!randInt) throw new Error('Failed to generate random integer');
		v[i] = new BN(randInt.toString());
	}
	return v;
}

function evaluatePolynomial(ec: EC, threshold: number, v: BN[], id: BN): BN {
	if (!ec.n) {
		throw new Error("ec.n is undefined");
	}
	const modN = new ModInt(ec.n);
	let result = v[0].clone();
	let X = new BN(1);

	for (let i = 1; i <= threshold; i++) {
		const ai = v[i];
		X = modN.mul(X, id) as BN;
		const aiXi = ai.mul(X);
		result = modN.add(result, aiXi) as BN;
	}

	return result;
}