import BN from 'bn.js';
import { ec as EC } from 'elliptic';
import { ECPoint } from './ECPoint';
import ModInt from '../common/ModInt';
import crypto from 'crypto';

export class Share {
	constructor(
		public threshold: number,
		public id: BN,      // xi
		public share: BN    // Sigma i
	) { }
	


	public verify(curve: EC, threshold: number, points: ECPoint[]): boolean {

		// Verify that the share lies on the polynomial defined by the points

		let lhs = curve.g.scalarMult(this.share);

		let rhs = points[0];

		let t = this.id;



		for (let i = 1; i <= threshold; i++) {

			rhs = rhs.add(points[i].scalarMult(t));

			t = t.mul(this.id).mod(curve.n);

		}



		return lhs.equals(rhs);

	}

}

export type Vs = ECPoint[]; // v0..vt

export class Shares {
	private shares: BN[];
	[index: number]: Share;

	constructor() {
		this.shares = [];
	}

	public addShare(share: BN): void {
		this.shares.push(share);
	}

	public getShare(index: number): BN {
		return this.shares[index];
	}

	public length(): number {
		return this.shares.length;
	}

	public map<T>(callback: (share: Share, index: number) => T): T[] {
		return Array.from({ length: this.shares.length }, (_, i) => callback(this[i], i));
	}
}

const zero = new BN(0);
const one = new BN(1);

export class VSS {
	static checkIndexes(ec: EC, indexes: BN[]): BN[] {
		const visited = new Map<string, boolean>();
		for (const v of indexes) {
			if (!ec.n) {
				throw new Error("Invalid elliptic curve parameter: n is undefined or null");
			}
			const vMod = v.mod(ec.n);
			if (vMod.eq(zero)) {
				throw new Error("party index should not be 0");
			}
			const vModStr = vMod.toString();
			if (visited.has(vModStr)) {
				throw new Error(`duplicate indexes ${vModStr}`);
			}
			visited.set(vModStr, true);
		}
		return indexes;
	}

	static create(ec: EC, threshold: number, secret: BN, indexes: BN[]): [Vs, Shares] {
		if (!secret || !indexes) {
			throw new Error("vss secret or indexes == nil");
		}
		if (threshold < 1) {
			throw new Error("vss threshold < 1");
		}

		const ids = this.checkIndexes(ec, indexes);
		const num = indexes.length;
		if (num < threshold) {
			throw new Error("not enough shares to satisfy the threshold");
		}

		const poly = this.samplePolynomial(ec, threshold, secret);

		const v: Vs = poly.map(ai => ECPoint.scalarBaseMult(ec, ai));

		const shares = new Shares();
		indexes.forEach(id => {
			const share = this.evaluatePolynomial(ec, threshold, poly, id);
			shares.addShare(new Share(threshold, id, share).share);
		});

		return [v, shares];
	}

	static verify(share: Share, ec: EC, threshold: number, vs: Vs): boolean {
		if (share.threshold !== threshold || !vs || vs.length !== threshold + 1) {
			return false;
		}

		if (!ec.n) {
			throw new Error("Invalid elliptic curve parameter: n is undefined or null");
		}
		const modQ = new ModInt(ec.n);
		let v = vs[0];
		let t = one.clone();

		try {
			for (let j = 1; j <= threshold; j++) {
				// t = k_i^j
				t = new BN(modQ.mul(t, share.id).toString());
				// v = v * v_j^t
				const vjt = vs[j].scalarMult(t);
				v = v.add(vjt);
			}
			const sigmaGi = ECPoint.scalarBaseMult(ec, share.share);
			return sigmaGi.equals(v);
		} catch {
			return false;
		}
	}

	static reconstruct(shares: Shares, ec: EC): BN {
		if (!shares || shares[0].threshold > shares.length()) {
			throw new Error("not enough shares to satisfy the threshold");
		}
		if (!ec.n) {
			throw new Error("Invalid elliptic curve parameter: n is undefined or null");
		}
		const modN = new ModInt(ec.n);
		const xs = shares.map(share => share.id);
		let secret = zero.clone();

		for (let i = 0; i < shares.length(); i++) {
			let times = one.clone();
			for (let j = 0; j < xs.length; j++) {
				if (j === i) continue;
				const sub = modN.sub(xs[j], shares[i].id);
				const subInv = modN.modInverse(sub);
				const div = new BN(modN.mul(xs[j], subInv).toString());
				times = new BN(modN.mul(times, div).toString());
			}
			const fTimes = modN.mul(shares[i].share, times);
			secret = new BN(modN.add(secret, fTimes).toString());
		}

		return secret;
	}

	private static samplePolynomial(ec: EC, threshold: number, secret: BN): BN[] {
		const q = ec.n;
		const v: BN[] = new Array(threshold + 1);
		v[0] = secret;
		for (let i = 1; i <= threshold; i++) {
			const randBuf = crypto.randomBytes(32);
			if (!q) {
				throw new Error("Failed to generate random bytes");
			}
			const ai = new BN(randBuf).mod(q);
			v[i] = ai;
		}
		return v;
	}

	private static evaluatePolynomial(ec: EC, threshold: number, v: BN[], id: BN): BN {
		if (!ec.n) {
			throw new Error("Invalid elliptic curve parameter: n is undefined or null");
		}
		const modQ = new ModInt(ec.n);
		let result = v[0].clone();
		let X = new BN(1);

		for (let i = 1; i <= threshold; i++) {
			const ai = v[i];
			X = new BN(modQ.mul(X, id).toString());
			const aiXi = ai.mul(X);
			result = new BN(modQ.add(result, aiXi).toString());
		}

		return result;
	}
}