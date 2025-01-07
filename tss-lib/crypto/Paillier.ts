import BN from 'bn.js';

import { ECPoint } from './ECPoint';
import { SHA512_256 } from '../common/Hash';
import { getRandomPositiveRelativelyPrimeInt } from '../common/Random';
import { PaillierPublicKey, PaillierPrivateKey } from '../common/Types';
import ModInt from '../common/ModInt';

const ProofIters = 13;
const verifyPrimesUntil = 1000;
const pQBitLenDifference = 3;

export class PublicKeyImpl implements PaillierPublicKey {
    constructor(public readonly N: BN) {}

    public NSquare(): BN {
        return this.N.mul(this.N);
    }

    public gamma(): BN {
        return this.N.add(new BN(1));
    }
}

export class PrivateKeyImpl implements PaillierPrivateKey {
    constructor(
        public readonly publicKey: PaillierPublicKey,
        public readonly lambdaN: BN,
        public readonly phiN: BN,
        public readonly P: BN,
        public readonly Q: BN
    ) {}
}

export class PublicKey {
	constructor(public N: BN) { }

	public NSquare(): BN {
		return this.N.mul(new BN(1));
	}

	public gamma(): BN {
		return this.N.add(new BN(1));
	}

	public async encrypt(m: BN): Promise<[BN, BN]> {
		if (m.ltn(0) || m.gte(this.N)) {
			throw new Error("message too long");
		}
		const x = getRandomPositiveRelativelyPrimeInt(this.N) as BN;
		const N2 = this.NSquare();
		const modN2 = new ModInt(N2);
		// 1. gamma^m mod N2
		const Gm = modN2.pow(this.gamma(), m);
		// 2. x^N mod N2
		const xN = modN2.pow(x, this.N);
		// 3. (1) * (2) mod N2
		const c = modN2.mul(Gm, xN);

		return [c, x];
	}

	public homoAdd(c1: BN, c2: BN): BN {
		const N2 = this.NSquare();
		if (c1.ltn(0) || c1.gte(N2) || c2.ltn(0) || c2.gte(N2)) {
			throw new Error("ciphertext too long");
		}
		return c1.mul(c2).mod(N2);
	}

	public homoMult(m: BN, c1: BN): BN {
		if (m.ltn(0) || m.gte(this.N)) {
			throw new Error("message too long");
		}
		const N2 = this.NSquare();
		if (c1.ltn(0) || c1.gte(N2)) {
			throw new Error("ciphertext too long");
		}
		return c1.pow(m).mod(N2);
	}
}

export class PrivateKey {
	constructor(
		public publicKey: PublicKey,
		public lambdaN: BN,
		public phiN: BN,
		public P: BN,
		public Q: BN
	) { }

	public decrypt(c: BN): BN {
		const N2 = this.publicKey.NSquare();
		if (c.ltn(0) || c.gte(N2)) {
			throw new Error("ciphertext too long");
		}

		if (!c.gcd(N2).eq(new BN(1))) {
			throw new Error("malformed message");
		}

		// 1. L(u) = (c^LambdaN-1 mod N2) / N
		const Lc = L(c.pow(this.lambdaN).mod(N2), this.publicKey.N);
		// 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
		const Lg = L(this.publicKey.gamma().pow(this.lambdaN).mod(N2), this.publicKey.N);
		// 3. (1) * modInv(2) mod N
		const inv = Lg.invm(this.publicKey.N);
		return Lc.mul(inv).mod(this.publicKey.N);
	}

	public proof(k: BN, ecdsaPub: ECPoint): BN[] {
		const pi: BN[] = new Array(ProofIters);
		const xs = generateXs(ProofIters, k, this.publicKey.N, ecdsaPub);

		for (let i = 0; i < ProofIters; i++) {
			const M = this.publicKey.N.invm(this.phiN);
			pi[i] = xs[i].pow(M).mod(this.publicKey.N);
		}

		return pi;
	}
}

export class PaillierProof {
	constructor(private values: BN[]) { }

	public static fromBytes(bytes: Buffer): PaillierProof {
		const values = Array(ProofIters).fill(null).map((_, i) => {
			const start = i * 32;
			return new BN(bytes.slice(start, start + 32));
		});
		return new PaillierProof(values);
	}

	public verify(pkN: BN, k: BN, ecdsaPub: ECPoint): boolean {
		// Check N for small prime factors
		for (let p = 2; p < verifyPrimesUntil; p++) {
			if (pkN.modn(p) === 0) {
				return false;
			}
		}

		const xs = generateXs(ProofIters, k, pkN, ecdsaPub);

		for (let i = 0; i < ProofIters; i++) {
			const xiModN = xs[i].mod(pkN);
			const yiExpN = this.values[i].pow(pkN).mod(pkN);
			if (!xiModN.eq(yiExpN)) {
				return false;
			}
		}

		return true;
	}

	public serialize(): Buffer {
		return Buffer.concat(this.values.map(v => v.toArrayLike(Buffer, 'be', 32)));
	}
}

function L(u: BN, N: BN): BN {
	return u.subn(1).div(N);
}

function generateXs(m: number, k: BN, N: BN, ecdsaPub: ECPoint): BN[] {
	const ret: BN[] = new Array(m);
	let i = 0, n = 0;

	const kb = k.toBuffer();
	const sXb = ecdsaPub.X().toBuffer();
	const sYb = ecdsaPub.Y().toBuffer();
	const Nb = N.toBuffer();

	while (i < m) {
		const blocks: Buffer[] = [];
		const ib = Buffer.from(i.toString());
		const nb = Buffer.from(n.toString());

		for (let j = 0; j < Math.ceil(N.bitLength() / 256); j++) {
			const jb = Buffer.from(j.toString());
			const hash = SHA512_256(ib, jb, nb, kb, sXb, sYb, Nb);
			blocks.push(hash);
		}

		const xi = new BN(Buffer.concat(blocks));
		if (xi.gcd(N).eq(new BN(1))) {
			ret[i] = xi;
			i++;
		} else {
			n++;
		}
	}

	return ret;
}