import BN from 'bn.js';
import crypto from 'crypto';
import ModInt  from '../common/ModInt';
import { SHA512_256i_TAGGED, RejectionSample } from '../common/Hash';
import { getRandomQuadraticNonResidue } from '../common/Random';

const Iterations = 80;
const ProofModBytesParts = Iterations * 2 + 3;

export class ModProof {
	private readonly w: BN;
	private readonly x: BN[];
	private readonly a: BN;
	private readonly b: BN;
	private readonly z: BN[];

	constructor(w: BN, x: BN[], a: BN, b: BN, z: BN[]) {
		this.w = w;
		this.x = x;
		this.a = a;
		this.b = b;
		this.z = z;
	}

	public getProof(): { w: BN; x: BN[]; a: BN; b: BN; z: BN[] } {
		return {
			w: this.w,
			x: this.x,
			a: this.a,
			b: this.b,
			z: this.z
		};
	}

	public verify(session: Buffer, N: BN): boolean {
		if (!this.validateBasic()) {
			return false;
		}
		if (isQuadraticResidue(this.w, N)) {
			return false;
		}
		if (this.w.isZero() || this.w.gte(N)) {
			return false;
		}
		for (let i = 0; i < Iterations; i++) {
			if (this.z[i].isZero() || this.z[i].gte(N)) {
				return false;
			}
			if (this.x[i].isZero() || this.x[i].gte(N)) {
				return false;
			}
		}
		if (this.a.bitLength() !== Iterations + 1) {
			return false;
		}
		if (this.b.bitLength() !== Iterations + 1) {
			return false;
		}

		const modN = new ModInt(N);
		const Y: BN[] = new Array(Iterations);
		for (let i = 0; i < Iterations; i++) {
			const ei = SHA512_256i_TAGGED(session, this.w, N, ...Y.slice(0, i));
			Y[i] = RejectionSample(N, ei);
		}

		const chs = new Array(Iterations * 2).fill(false);
		for (let i = 0; i < Iterations; i++) {
			const left = modN.exp(this.z[i], N);
			if (!left.eq(Y[i])) {
				return false;
			}
			chs[i] = true;

			const a = this.a.testn(i) ? 1 : 0;
			const b = this.b.testn(i) ? 1 : 0;
			if (a !== 0 && a !== 1) {
				return false;
			}
			if (b !== 0 && b !== 1) {
				return false;
			}
			const left2 = modN.exp(this.x[i], new BN(4));
			let right = Y[i];
			if (a > 0) {
				right = modN.mul(new BN(-1), right);
			}
			if (b > 0) {
				right = modN.mul(this.w, right);
			}
			if (!left2.eq(right)) {
				return false;
			}
			chs[Iterations + i] = true;
		}

		return chs.every(ch => ch);
	}

	public static newProof(session: Buffer, N: BN, P: BN, Q: BN, rand: crypto.RandomSource): ModProof {
		const Phi = P.sub(new BN(1)).mul(Q.sub(new BN(1)));
		const W = getRandomQuadraticNonResidue(rand, N);

		const Y: BN[] = new Array(Iterations);
		for (let i = 0; i < Iterations; i++) {
			const ei = SHA512_256i_TAGGED(session, W, N, ...Y.slice(0, i));
			Y[i] = RejectionSample(N, ei);
		}

		const modN = new ModInt(N);
		const modPhi = new ModInt(Phi);
		const invN = N.invm(Phi);
		const X: BN[] = new Array(Iterations);
		const A = new BN(1).shln(Iterations);
		const B = new BN(1).shln(Iterations);
		const Z: BN[] = new Array(Iterations);

		const expo = Phi.add(new BN(4)).shrn(3).mul(Phi.add(new BN(4)).shrn(3));

		for (let i = 0; i < Iterations; i++) {
			for (let j = 0; j < 4; j++) {
				const a = j & 1;
				const b = (j & 2) >> 1;
				let Yi = Y[i].clone();
				if (a > 0) {
					Yi = modN.mul(new BN(-1), Yi);
				}
				if (b > 0) {
					Yi = modN.mul(W, Yi);
				}
				if (isQuadraticResidue(Yi, P) && isQuadraticResidue(Yi, Q)) {
					const Xi = modN.exp(Yi, expo);
					const Zi = modN.exp(Y[i], invN);
					X[i] = Xi;
					Z[i] = Zi;
					A.setn(i, a);
					B.setn(i, b);
					break;
				}
			}
		}

		return new ModProof(W, X, A, B, Z);
	}

	public validateBasic(): boolean {
		if (!this.w) {
			return false;
		}
		for (let i = 0; i < Iterations; i++) {
			if (!this.x[i] || !this.z[i]) {
				return false;
			}
		}
		if (!this.a || !this.b) {
			return false;
		}
		return true;
	}

	public serialize(): Buffer[] {
		const parts = [this.w, ...this.x, this.a, this.b, ...this.z];
		return parts.map(part => part.toArrayLike(Buffer));
	}

	public static unmarshalModProof(bzs: Buffer[]): ModProof {
		const bis = bzs.map(bz => new BN(bz));
		const w = bis[0];
		const x = bis.slice(1, Iterations + 1);
		const a = bis[Iterations + 1];
		const b = bis[Iterations + 2];
		const z = bis.slice(Iterations + 3, ProofModBytesParts);
		return new ModProof(w, x, a, b, z);
	}
}

function isQuadraticResidue(X: BN, N: BN): boolean {
	return X.jacobi(N) === 1;
}