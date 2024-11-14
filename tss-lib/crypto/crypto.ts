import BN from 'bn.js';
import crypto from 'crypto';

const Iterations = 128;

class DLNProof {
    private alpha: BN[];
    private t: BN[];

    constructor(alpha: BN[], t: BN[]) {
        this.alpha = alpha;
        this.t = t;
    }

    public static newDLNProof(h1: BN, h2: BN, x: BN, p: BN, q: BN, N: BN): DLNProof {
        const pMulQ = p.mul(q);
        const modN = (base: BN) => base.mod(N);
        const modPQ = (base: BN) => base.mod(pMulQ);
        const a: BN[] = [];
        const alpha: BN[] = new Array(Iterations);
        for (let i = 0; i < Iterations; i++) {
            a[i] = new BN(crypto.randomBytes(pMulQ.byteLength()));
            alpha[i] = modN(h1.pow(a[i]));
        }
        const msg = [h1, h2, N, ...alpha];
        const c = new BN(crypto.createHash('sha256').update(Buffer.concat(msg.map(m => m.toArrayLike(Buffer)))).digest('hex'), 16);
        const t: BN[] = new Array(Iterations);
        for (let i = 0; i < Iterations; i++) {
            const cI = c.testn(i) ? new BN(1) : new BN(0);
            t[i] = modPQ(a[i].add(modPQ(cI.mul(x))));
        }
        return new DLNProof(alpha, t);
    }

    public verify(h1: BN, h2: BN, N: BN): boolean {
        if (!N.isZero() && N.isNeg()) {
            return false;
        }
        const modN = (base: BN) => base.mod(N);
        const h1_ = h1.mod(N);
        if (h1_.lte(new BN(1)) || h1_.gte(N)) {
            return false;
        }
        const h2_ = h2.mod(N);
        if (h2_.lte(new BN(1)) || h2_.gte(N)) {
            return false;
        }
        if (h1_.eq(h2_)) {
            return false;
        }
        for (let i = 0; i < Iterations; i++) {
            const a = this.t[i].mod(N);
            if (a.lte(new BN(1)) || a.gte(N)) {
                return false;
            }
        }
        for (let i = 0; i < Iterations; i++) {
            const a = this.alpha[i].mod(N);
            if (a.lte(new BN(1)) || a.gte(N)) {
                return false;
            }
        }
        const msg = [h1, h2, N, ...this.alpha];
        const c = new BN(crypto.createHash('sha256').update(Buffer.concat(msg.map(m => m.toArrayLike(Buffer)))).digest('hex'), 16);
        for (let i = 0; i < Iterations; i++) {
            const cI = c.testn(i) ? new BN(1) : new BN(0);
            const h1ExpTi = modN(h1.pow(this.t[i]));
            const h2ExpCi = modN(h2.pow(cI));
            const alphaIMulH2ExpCi = modN(this.alpha[i].mul(h2ExpCi));
            if (!h1ExpTi.eq(alphaIMulH2ExpCi)) {
                return false;
            }
        }
        return true;
    }

    public serialize(): Buffer[] {
        const parts = [this.alpha, this.t];
        return parts.map(part => Buffer.concat(part.map(p => p.toArrayLike(Buffer))));
    }

    public static unmarshalDLNProof(bzs: Buffer[]): DLNProof {
        const bis = bzs.map(bz => new BN(bz));
        const alpha = bis.slice(0, Iterations);
        const t = bis.slice(Iterations, 2 * Iterations);
        return new DLNProof(alpha, t);
    }
}

export { DLNProof };