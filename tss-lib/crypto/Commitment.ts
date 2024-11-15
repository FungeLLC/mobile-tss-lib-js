import BN from 'bn.js';
import crypto from 'crypto';
import { SHA512_256i } from '../common/Hash';
import { ECPoint } from './ECPoint';

export class HashCommitDecommit {
    constructor(
        public C: BN, // commitment
        public D: BN[] // decommitment
    ) {}

    static createCommitment(...values: BN[]): HashCommitDecommit {
        // Generate random nonce
        const nonce = new BN(crypto.randomBytes(32));

        // Create hash with nonce and values
        const parts = [nonce, ...values];
        const hash = SHA512_256i(...parts);

        return new HashCommitDecommit(hash, parts);
    }

    static createCommitmentWithRandomness(r: BN, ...values: BN[]): HashCommitDecommit {
        const parts = [r, ...values];
        const hash = SHA512_256i(...parts);

        return new HashCommitDecommit(hash, parts);
    }

    verify(): boolean {
        if (!this.D || this.D.length < 1) {
            return false;
        }

        // Reconstruct hash
        const hash = SHA512_256i(...this.D);

        // Verify commitment matches
        return this.C.eq(hash);
    }

    deCommit(): [boolean, BN[]] {
        if (this.verify()) {
            // [1:] skips random element r in D
            return [true, this.D.slice(1)];
        } else {
            return [false, []];
        }
    }

    static fromECPoints(points: ECPoint[]): HashCommitDecommit {
        const buffers = points.map(p => {
            const x = p.X().toArrayLike(Buffer);
            const y = p.Y().toArrayLike(Buffer);
            return Buffer.concat([x, y]);
        });
        return HashCommitDecommit.createCommitment(...buffers.map(b => new BN(b)));
    }

    static fromBNs(nums: BN[]): HashCommitDecommit {
        return HashCommitDecommit.createCommitment(...nums);
    }

    static async verify(commitment: HashCommitDecommit, decommitment: BN[]): Promise<boolean> {
        const hcd = new HashCommitDecommit(commitment.C, decommitment);
        return hcd.verify();
    }
}

export class HashCommitment {
    static new(...values: BN[]): HashCommitDecommit {
        return HashCommitDecommit.createCommitment(...values);
    }
}

export default {
    HashCommitment,
    HashCommitDecommit
};