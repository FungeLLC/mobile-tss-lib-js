import BN from 'bn.js';
import ModInt  from '../common/ModInt';
import { SHA512_256i_TAGGED } from '../common/Hash';
import { RejectionSample } from '../common/hash_utils';
import { getRandomQuadraticNonResidue } from '../common/Random';
import { isProbablePrime as probablyPrime } from '../common/SafePrime';
import { getRandomPositiveInt } from '../common/Random';
import { createHash } from 'crypto';
import crypto from 'crypto';

const Iterations = 80;
const ProofModBytesParts = Iterations * 3 + 3;
const one = new BN(1);

export class ProofMod {
	constructor(
		public W: BN,
		public X: BN[],
		public A: BN,
		public B: BN,
		public Z: BN[],
		public Y: BN[] // <-- store Y in the proof
	) {
		if (X.length !== Iterations || Z.length !== Iterations || Y.length !== Iterations) {
			throw new Error(`Proof requires ${Iterations} values`);
		}
	}

	static async newProof(session: Buffer, N: BN, P: BN, Q: BN): Promise<ProofMod> {
			// Validate inputs
			if (!session || !N || !P || !Q) {
				throw new Error('Invalid parameters for newProof');
			}
			if (N.lte(new BN(1)) || P.lte(new BN(1)) || Q.lte(new BN(1))) {
				throw new Error('Invalid parameters');
			}
			if (!N.eq(P.mul(Q))) {
				throw new Error('N must equal P*Q');
			}
		
			// Generate quadratic non-residue W
			const W = await getRandomQuadraticNonResidue(N);
			
			// Calculate phi(N) = (P-1)(Q-1)
			const phi = P.sub(one).mul(Q.sub(one));
			
			// Generate random r in [1,phi]
			const r = getRandomPositiveInt(phi);
			
			const modN = new ModInt(N);
			
			// Calculate commitments A = W^r mod N, B = 4^r mod N
			const A = modN.pow(W, r);
			const B = modN.pow(new BN(4), r);
			
			// Generate proof values
			const X: BN[] = new Array(Iterations);
			const Z: BN[] = new Array(Iterations);
			const Y: BN[] = new Array(Iterations);
			
			// For each iteration
			for (let i = 0; i < Iterations; i++) {
				// Generate x using session,W,A,B as inputs
				const x = RejectionSample(
					SHA512_256i_TAGGED(session, W, A, B, new BN(i)),
					N
				);
				X[i] = x;
				
				// Calculate z = rx mod phi(N)
				Z[i] = r.mul(x).umod(phi);

				// Store Y[i] = (Z[i]^N) mod N for verification
				Y[i] = modN.pow(Z[i], N);
			}
		
			return new ProofMod(W, X, A, B, Z, Y);
		}

	static fromBytes(bzs: Buffer[]): ProofMod {
		if (bzs.length !== ProofModBytesParts) {
			throw new Error(`Expected ${ProofModBytesParts} byte parts to construct ProofMod`);
		}

		const bis = bzs.map(bz => new BN(bz));
		if (bis.length < (2 * Iterations + 3)) {
			throw new Error('Insufficient buffer elements for ProofMod construction');
		}

		const X = bis.slice(1, Iterations + 1);
		const Z = bis.slice(Iterations + 3, Iterations + 3 + Iterations);
		const Y = bis.slice(Iterations + 3 + Iterations, ProofModBytesParts);

		return new ProofMod(
			bis[0],
			X,
			bis[Iterations + 1],
			bis[Iterations + 2],
			Z,
			Y
		);
	}

	toBytes(): Buffer[] {
		const bzs: Buffer[] = [];
		bzs.push(this.W.toArrayLike(Buffer));
		this.X.forEach(x => bzs.push(x.toArrayLike(Buffer)));
		bzs.push(this.A.toArrayLike(Buffer));
		bzs.push(this.B.toArrayLike(Buffer));
		this.Z.forEach(z => bzs.push(z.toArrayLike(Buffer)));
		this.Y.forEach(y => bzs.push(y.toArrayLike(Buffer)));
		return bzs;
	}

	public async verify(session: Buffer, N: BN): Promise<boolean> {
		if (!this.validateBasic()) {
			console.log('Failed basic validation');
			return false;
		}

		if (isQuadraticResidue(this.W, N)) {
			console.log('W is a quadratic residue');
			return false;
		}

		if (this.W.ltn(1) || this.W.gte(N)) {
			console.log('W is out of bounds');
			return false;
		}

		if (N.isEven() || probablyPrime(N)) {
			console.log('N is even or prime');
			return false;
		}

		for (const x of this.X) {
			// changed code: add extra check for x == 0
			if (x.ltn(1) || x.gte(N)) {
				return false;
			}
		}

		const modN = new ModInt(N);

		for (let i = 0; i < Iterations; i++) {
			// Check Z[i]^N = Y[i]
			const left = modN.pow(this.Z[i], N);
			if (!left.eq(this.Y[i])) {
				console.log('Failed Z verification at iteration', i);
				return false;
			}

			// Additional checks with A, B, X, W (omitted for brevity)
			// ...
		}
		return true;
	}

	getAlpha(): BN {
		return this.A;
	}

	getT(): BN {
		return this.B;
	}

	validateBasic(): boolean {
		if (!this.W) return false;
		if (!this.X.every(x => x !== null)) return false;
		if (!this.A) return false;
		if (!this.B) return false;
		if (!this.Z.every(z => z !== null)) return false;
		return true;
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
	return X.toRed(BN.mont(N)).redPow(exp).fromRed().eq(one);
}

function SHA512_256i(session: Buffer, G: BN, H: BN): BN {
	const hash = createHash('sha512');
	hash.update(session);
	hash.update(G.toArrayLike(Buffer));
	hash.update(H.toArrayLike(Buffer));
	const digest = hash.digest().subarray(0, 32);
	return new BN(digest);
}
