import BN from 'bn.js';
import ModInt from '../common/ModInt';
import { SHA512_256i } from '../common/Hash';
import { getRandomPositiveInt } from '../common/Random';
import crypto from 'crypto';
import { RandomBytesProvider } from '../common/Types';

const Iterations = 128;
const one = new BN(1);

// export interface RandomBytesProvider {
// 	randomBytes: (size: number) => Buffer;
// }

// dlnproof.ts
export class DLNProof {
	constructor(
		private Alpha: BN[],
		private T: BN[]
	) {
		if (Alpha.length !== Iterations || T.length !== Iterations) {
			throw new Error(`Proof requires ${Iterations} values`);
		}
	}

	public getAlpha(): BN[] {
		return this.Alpha;
	}

	public getT(): BN[] {
		return this.T;
	}

	public getXValues(): BN[] {
		return this.Alpha;
	}

	public getEValues(): BN[] {
		return this.T;
	}

	public serialize(): Buffer {
		const alpha = Buffer.concat(this.Alpha.map(a => a.toArrayLike(Buffer)));
		const t = Buffer.concat(this.T.map(t => t.toArrayLike(Buffer)));
		return Buffer.concat([alpha, t]);
	}

	public static unmarshalDLNProof(buf: Buffer): DLNProof {
		const alpha: BN[] = [];
		const t: BN[] = [];
		const len = buf.length / 2;
		for (let i = 0; i < len; i++) {
			alpha.push(new BN(buf.slice(i * 32, (i + 1) * 32)));
			t.push(new BN(buf.slice(len * 32 + i * 32, len * 32 + (i + 1) * 32)));
		}
		return new DLNProof(alpha, t);
	}

	public static newDLNProof(h1: BN, h2: BN, x: BN, p: BN, q: BN, N: BN, rand?: Partial<RandomBytesProvider>): DLNProof {
		console.log('Starting DLN Proof generation');
		console.log(`pMulQ bits: ${p.mul(q).bitLength()}`);

		const pMulQ = p.mul(q);
		// Remove modulus check as it's not applicable in static method
		const modN = new ModInt(N);
		const modPQ = new ModInt(pMulQ);

		if (!rand) {
			rand = { randomBytes: (size: number) => crypto.randomBytes(size) };
		}

		console.log('Generating random values and computing alpha...');
		const a: BN[] = new Array(Iterations);
		const alpha: BN[] = new Array(Iterations);
		
		// Pre-compute window for h1
		const windowSize = 4;
		const h1Window = modN.precomputeWindow(h1, windowSize);

		for (let i = 0; i < Iterations; i++) {
			if (i % 32 === 0) {
				console.log(`Processing iteration ${i}/${Iterations}`);
			}

			try {
				const randomValue = getRandomPositiveInt(pMulQ) as BN;
				if (!randomValue || randomValue.cmp(pMulQ) >= 0) {
					console.error(`Failed to generate valid random value at iteration ${i}`);
					throw new Error(`Random value generation failed at iteration ${i}`);
				}
				a[i] = randomValue as BN;
				//process.stdout.write('got random value: ' + a[i].toString(16) + ' for iteration ' + i + '\n');
				// Use window optimization for faster exponentiation
				alpha[i] = modN.expWindow(h1, a[i], windowSize, h1Window) as BN;
				if (!alpha[i]) {
					console.error(`Failed to compute alpha at iteration ${i}`);
					throw new Error(`Alpha computation failed at iteration ${i}`);
				}
				//process.stdout.write('computed alpha: ' + alpha[i].toString(16) + ' for iteration ' + i + '\n');
			} catch (error) {
				console.error(`Error at iteration ${i}:`, error);
				throw error;
			}
		}

		process.stdout.write('Computing challenge...');
		const msg = [h1, h2, N, ...alpha];
		const c = SHA512_256i(...msg);

		process.stdout.write('Computing responses...');
		const t: BN[] = new Array(Iterations);
		for (let i = 0; i < Iterations; i++) {
			const cI = c.testn(i) ? new BN(1) : new BN(0);
			t[i] = modPQ.add(a[i], modPQ.mul(cI, x)) as BN;
			//process.stdout.write('computed t: ' + t[i].toString(16) + ' for iteration ' + i + '\n');
		}

		process.stdout.write('DLN Proof generation complete');
		return new DLNProof(alpha, t);
	}

	public verify(h1: BN, h2: BN, N: BN): boolean {
		if (!this.Alpha || !this.T || this.Alpha.length !== Iterations || this.T.length !== Iterations) {
			console.error('Invalid proof structure');
			return false;
		}
		if (N.lten(0)) {
			console.error('Invalid modulus N');
			return false;
		}

		const modN = new ModInt(N);
		const h1_ = h1.mod(N);
		const h2_ = h2.mod(N);

		// Early validation
		if (h1_.cmp(one) !== 1 || h1_.cmp(N) !== -1) return false;
		if (h2_.cmp(one) !== 1 || h2_.cmp(N) !== -1) return false;
		if (h1_.cmp(h2_) === 0) return false;

		console.log('Starting DLN Proof verification');

		// Pre-validate all T and Alpha values
		for (let i = 0; i < Iterations; i++) {
			if (!this.T[i] || !this.Alpha[i]) return false;
			const t = this.T[i].mod(N);
			const alpha = this.Alpha[i].mod(N);
			if (t.cmp(one) !== 1 || t.cmp(N) !== -1) return false;
			if (alpha.cmp(one) !== 1 || alpha.cmp(N) !== -1) return false;
		}

		console.log('Pre-validation complete');

		// Pre-compute windows for faster exponentiation
		const windowSize = 8;
		const h1Window = modN.precomputeWindow(h1, windowSize);
		const h2Window = modN.precomputeWindow(h2, windowSize);

		const msg = [h1, h2, N, ...this.Alpha];
		const c = SHA512_256i(...msg);

		console.log('Computing responses...');

		for (let i = 0; i < Iterations; i++) {
			const cI = c.testn(i) ? new BN(1) : new BN(0);
			const ti = this.T[i].mod(N);
			const alphai = this.Alpha[i].mod(N);
			
			// Calculate h1^ti mod N
			const h1ExpTi = modN.expWindow(h1, ti, windowSize, h1Window) as BN;
			// Calculate h2^ci mod N (if ci is 0, this is 1)
			const h2ExpCi = cI.isZero() ? new BN(1) : modN.expWindow(h2, cI, windowSize, h2Window) as BN;
			// Calculate (alphai * h2^ci) mod N
			const alphaIMulH2ExpCi = modN.mul(alphai, h2ExpCi) as BN;

			// Verify that h1^ti ≡ alphai * h2^ci (mod N)
			if (h1ExpTi.mod(N).cmp(alphaIMulH2ExpCi.mod(N)) !== 0) {
				console.error(`Verification failed at iteration ${i}:\nh1ExpTi: ${h1ExpTi.toString(16)}\nalphaIMulH2ExpCi: ${alphaIMulH2ExpCi.toString(16)}\nT[${i}]: ${ti.toString(16)}\nAlpha[${i}]: ${alphai.toString(16)}\ncI: ${cI.toString()}`);
				return false;
			}
		}

		return true;
	}
}