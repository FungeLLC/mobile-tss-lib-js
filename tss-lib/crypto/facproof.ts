import BN from 'bn.js';
import crypto from 'crypto';

class ProofFac {
	public p: BN;
	public q: BN;
	public a: BN;
	public b: BN;
	public t: BN;
	public sigma: BN;
	public z1: BN;
	public z2: BN;
	public w1: BN;
	public w2: BN;
	public v: BN;

	constructor(
		p: BN = new BN(0),
		q: BN = new BN(0),
		a: BN = new BN(0),
		b: BN = new BN(0),
		t: BN = new BN(0),
		sigma: BN = new BN(0),
		z1: BN = new BN(0),
		z2: BN = new BN(0),
		w1: BN = new BN(0),
		w2: BN = new BN(0),
		v: BN = new BN(0)
	) {
		this.p = p;
		this.q = q;
		this.a = a;
		this.b = b;
		this.t = t;
		this.sigma = sigma;
		this.z1 = z1;
		this.z2 = z2;
		this.w1 = w1;
		this.w2 = w2;
		this.v = v;
	}

	public static newProof(
		context: Buffer,
		ec: any,
		n: BN,
		nTilde: BN,
		h1: BN,
		h2: BN,
		p: BN,
		q: BN,
	): ProofFac {
		const modN = (base: BN) => base.mod(n);
		const modNTilde = (base: BN) => base.mod(nTilde);

		const a = new BN(crypto.randomBytes(n.byteLength()));
		const b = new BN(crypto.randomBytes(n.byteLength()));
		const t = new BN(crypto.randomBytes(n.byteLength()));
		const sigma = new BN(crypto.randomBytes(n.byteLength()));
		const z1 = modN(a.add(p.mul(t)));
		const z2 = modN(b.add(q.mul(t)));
		const w1 = modNTilde(h1.pow(a));
		const w2 = modNTilde(h2.pow(b));
		const v = modNTilde(h1.pow(sigma).mul(h2.pow(t)));

		return new ProofFac(p, q, a, b, t, sigma, z1, z2, w1, w2, v);
	}

	public verify(context: Buffer, n: BN, nTilde: BN, h1: BN, h2: BN): boolean {
		const modN = (base: BN) => base.mod(n);
		const modNTilde = (base: BN) => base.mod(nTilde);

		const w1Check = modNTilde(h1.pow(this.a));
		const w2Check = modNTilde(h2.pow(this.b));
		const vCheck = modNTilde(h1.pow(this.sigma).mul(h2.pow(this.t)));

		return (
			this.w1.eq(w1Check) &&
			this.w2.eq(w2Check) &&
			this.v.eq(vCheck)
		);
	}
}

export { ProofFac };