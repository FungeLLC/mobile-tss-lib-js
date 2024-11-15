import BN from 'bn.js';
import ModInt  from '../common/ModInt';
import { SHA512_256i_TAGGED } from '../common/Hash';
import { RejectionSample } from '../common/Random';
import { getRandomQuadraticNonResidue } from '../common/Random';
import { probablyPrime } from '../common/SafePrime';

const Iterations = 80;
const ProofModBytesParts = Iterations * 2 + 3;
const one = new BN(1);

export class ProofMod {
	constructor(
		public W: BN,
		public X: BN[],
		public A: BN,
		public B: BN,
		public Z: BN[]
	) {
		if (X.length !== Iterations || Z.length !== Iterations) {
			throw new Error(`Proof requires ${Iterations} values`);
		}
	}

	static async newProof(session: Buffer, N: BN, P: BN, Q: BN): Promise<ProofMod> {
		const Phi = P.sub(one).mul(Q.sub(one));
		// Fig 16.1
		const W = getRandomQuadraticNonResidue(N);

		// Fig 16.2
		const Y: BN[] = new Array(Iterations);
		for (let i = 0; i < Iterations; i++) {
			const ei = SHA512_256i_TAGGED(session, W, N, ...Y.slice(0, i));
			Y[i] = RejectionSample(N, ei);
		}

		// Fig 16.3
		const modN = new ModInt(N);
		const modPhi = new ModInt(Phi);
		const invN = N.invm(Phi);
		const X: BN[] = new Array(Iterations);
		// Fix bitLen of A and B
		const A = one.shln(Iterations);
		const B = one.shln(Iterations);
		const Z: BN[] = new Array(Iterations);

		// for fourth-root
		let expo = Phi.add(new BN(4));
		expo = expo.shrn(3);
		expo = new BN(modPhi.mul(expo, expo).toString());

		for (let i = 0; i < Iterations; i++) {
			for (let j = 0; j < 4; j++) {
				const a = j & 1;
				const b = (j & 2) >> 1;
				let Yi = Y[i].clone();
				if (a > 0) {
					Yi = new BN(modN.mul(new BN(-1), Yi).toString());
				}
				if (b > 0) {
					Yi = new BN(modN.mul(W, Yi).toString());
				}
				if (isQuadraticResidue(Yi, P) && isQuadraticResidue(Yi, Q)) {
					const Xi = modN.exp(Yi, expo);
					const Zi = modN.exp(Y[i], invN);
					X[i] = new BN(Xi.toString());
					Z[i] = new BN(Zi.toString());
					A.setn(i, a as 0 | 1);
					B.setn(i, b as 0 | 1);
					break;
				}
			}
		}

		return new ProofMod(W, X, A, B, Z);
	}

	static fromBytes(bzs: Buffer[]): ProofMod {
		if (bzs.length !== ProofModBytesParts) {
			throw new Error(`Expected ${ProofModBytesParts} byte parts to construct ProofMod`);
		}

		const bis = bzs.map(bz => new BN(bz));
		const X = bis.slice(1, Iterations + 1);
		const Z = bis.slice(Iterations + 3);

		return new ProofMod(
			bis[0],
			X,
			bis[Iterations + 1],
			bis[Iterations + 2],
			Z
		);
	}

	async verify(session: Buffer, N: BN): Promise<boolean> {
		if (!this.validateBasic()) {
			return false;
		}

		if (isQuadraticResidue(this.W, N)) {
			return false;
		}

		if (this.W.ltn(1) || this.W.gte(N)) {
			return false;
		}

		for (const z of this.Z) {
			if (z.ltn(1) || z.gte(N)) {
				return false;
			}
		}

		for (const x of this.X) {
			if (x.ltn(1) || x.gte(N)) {
				return false;
			}
		}

		if (this.A.bitLength() !== Iterations + 1) {
			return false;
		}

		if (this.B.bitLength() !== Iterations + 1) {
			return false;
		}

		const modN = new ModInt(N);
		const Y: BN[] = new Array(Iterations);
		for (let i = 0; i < Iterations; i++) {
			const ei = SHA512_256i_TAGGED(session, this.W, N, ...Y.slice(0, i));
			Y[i] = RejectionSample(N, ei);
		}

		// Fig 16. Verification
		if (N.isEven() || probablyPrime(N)) {
			return false;
		}

		const verificationPromises: Promise<boolean>[] = [];

		for (let i = 0; i < Iterations; i++) {
			verificationPromises.push(
				Promise.resolve().then(() => {
					const left = modN.exp(this.Z[i], N);
					return new BN(left.toString()).eq(Y[i]);
				})
			);

			verificationPromises.push(
				Promise.resolve().then(() => {
					const a = this.A.testn(i);
					const b = this.B.testn(i);
					if (typeof a !== 'boolean' || typeof b !== 'boolean') {
						return false;
					}
					const left = new BN(modN.exp(this.X[i], new BN(4)).toString());
					let right = Y[i];
					if (a) {
						right = new BN(modN.mul(new BN(-1), right).toString());
					}
					if (b) {
						right = new BN(modN.mul(this.W, right).toString());
					}
					return left.eq(right);
				})
			);
		}

		const results = await Promise.all(verificationPromises);
		return results.every(result => result);
	}

	validateBasic(): boolean {
		if (!this.W) return false;
		if (!this.X.every(x => x !== null)) return false;
		if (!this.A) return false;
		if (!this.B) return false;
		if (!this.Z.every(z => z !== null)) return false;
		return true;
	}

	toBytes(): Buffer[] {
		const bzs: Buffer[] = [];
		bzs.push(this.W.toArrayLike(Buffer));
		this.X.forEach(x => bzs.push(x.toArrayLike(Buffer)));
		bzs.push(this.A.toArrayLike(Buffer));
		bzs.push(this.B.toArrayLike(Buffer));
		this.Z.forEach(z => bzs.push(z.toArrayLike(Buffer)));
		return bzs;
	}
}

function isQuadraticResidue(X: BN, N: BN): boolean {
	const gcd = X.gcd(N);
	if (!gcd.eq(one)) {
		return false;
	}
	// For prime N, Euler's criterion states that X is a quadratic residue
	// if and only if X^((N-1)/2) ≡ 1 (mod N)
	const exp = N.sub(one).divn(2);
	return X.pow(exp).mod(N).eq(one);
}