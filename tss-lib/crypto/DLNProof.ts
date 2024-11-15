import BN from 'bn.js';
import ModInt from '../common/ModInt';
import { SHA512_256i } from '../common/Hash';
import { getRandomPositiveInt } from '../common/Random';
import crypto from 'crypto';

const Iterations = 128;
const one = new BN(1);

export class DLNProof {
	constructor(
		private Alpha: BN[],
		private T: BN[]
	) {
		if (Alpha.length !== Iterations || T.length !== Iterations) {
			throw new Error(`Proof requires ${Iterations} values`);
		}
	}

	public static newDLNProof(h1: BN, h2: BN, x: BN, p: BN, q: BN, N: BN): DLNProof {
		const pMulQ = p.mul(q);
		const modN = new ModInt(N);
		const modPQ = new ModInt(pMulQ);

		// Generate random values and compute alpha
		const a: BN[] = new Array(Iterations);
		const alpha: BN[] = new Array(Iterations);

		for (let i = 0; i < Iterations; i++) {
			const randInt = getRandomPositiveInt(pMulQ);
			if (!randInt) throw new Error('Failed to generate random integer');
			a[i] = new BN(randInt.toString());
			alpha[i] = modN.exp(h1, a[i]) as BN;
		}

		// Compute challenge
		const msg = [h1, h2, N, ...alpha];
		const c = SHA512_256i(...msg);

		// Compute responses
		const t: BN[] = new Array(Iterations);
		for (let i = 0; i < Iterations; i++) {
			const cI = c.testn(i) ? new BN(1) : new BN(0);
			t[i] = modPQ.add(a[i], modPQ.mul(cI, x)) as BN;
		}

		return new DLNProof(alpha, t);
	}

	public verify(h1: BN, h2: BN, N: BN): boolean {
		if (!N.gt(new BN(0))) {
			return false;
		}

		const modN = new ModInt(N);
		const h1_ = h1.mod(N);
		const h2_ = h2.mod(N);

		// Basic checks
		if (h1_.lte(one) || h1_.gte(N)) return false;
		if (h2_.lte(one) || h2_.gte(N)) return false;
		if (h1_.eq(h2_)) return false;

		// Verify T values
		for (const t of this.T) {
			const a = t.mod(N);
			if (a.lte(one) || a.gte(N)) return false;
		}

		// Verify Alpha values
		for (const alpha of this.Alpha) {
			const a = alpha.mod(N);
			if (a.lte(one) || a.gte(N)) return false;
		}

		// Compute and verify proof
		const msg = [h1, h2, N, ...this.Alpha];
		const c = SHA512_256i(...msg);

		for (let i = 0; i < Iterations; i++) {
			if (!this.Alpha[i] || !this.T[i]) return false;

			const cI = c.testn(i) ? new BN(1) : new BN(0);
			const h1ExpTi = modN.exp(h1, this.T[i]) as BN;
			const h2ExpCi = modN.exp(h2, cI) as BN;
			const alphaIMulH2ExpCi = modN.mul(this.Alpha[i], h2ExpCi) as BN;

			if (!h1ExpTi.eq(alphaIMulH2ExpCi)) return false;
		}

		return true;
	}

	public serialize(): Buffer[] {
		const result: Buffer[] = [];

		// Serialize Alpha values
		for (const alpha of this.Alpha) {
			result.push(alpha.toBuffer());
		}

		// Serialize T values
		for (const t of this.T) {
			result.push(t.toBuffer());
		}

		return result;
	}

	public static unmarshalDLNProof(bzs: Buffer[]): DLNProof {
		if (bzs.length !== Iterations * 2) {
			throw new Error(`UnmarshalDLNProof expected ${Iterations * 2} parts but got ${bzs.length}`);
		}

		const alpha: BN[] = [];
		const t: BN[] = [];

		// Parse Alpha values
		for (let i = 0; i < Iterations; i++) {
			alpha.push(new BN(bzs[i]));
		}

		// Parse T values
		for (let i = 0; i < Iterations; i++) {
			t.push(new BN(bzs[i + Iterations]));
		}

		return new DLNProof(alpha, t);
	}
}