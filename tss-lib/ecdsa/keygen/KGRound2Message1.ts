import { ParsedMessage, PartyID } from './interfaces';
import BN from 'bn.js';
import { ProofFac } from '../../crypto/FACProof';

class KGRound2Message1 implements ParsedMessage {
    public content: any;
    public wireBytes: Buffer;
    public isBroadcast: boolean;

    constructor(
        public to: PartyID,
        public from: PartyID,
        public share: BN,
        public proof: ProofFac
    ) {
        this.content = {
            to: to,
            share: share.toString(16),
            facProof: {
                p: proof.p.toString(16),
                q: proof.q.toString(16),
                a: proof.a.toString(16),
                b: proof.b.toString(16),
                t: proof.t.toString(16),
                sigma: proof.sigma.toString(16),
                z1: proof.z1.toString(16),
                z2: proof.z2.toString(16),
                w1: proof.w1.toString(16),
                w2: proof.w2.toString(16),
                v: proof.v.toString(16)
            }
        };
        this.wireBytes = Buffer.from(JSON.stringify(this.content));
        this.isBroadcast = false;
    }

    public getFrom(): PartyID {
        return this.from;
    }

    public getContent(): any {
        return this.content;
    }

    public unmarshalShare(): BN {
        return new BN(this.content.share, 16);
    }

    public unmarshalFacProof(): ProofFac {
        return new ProofFac(
            new BN(this.content.facProof.p, 16),
            new BN(this.content.facProof.q, 16),
            new BN(this.content.facProof.a, 16),
            new BN(this.content.facProof.b, 16),
            new BN(this.content.facProof.t, 16),
            new BN(this.content.facProof.sigma, 16),
            new BN(this.content.facProof.z1, 16),
            new BN(this.content.facProof.z2, 16),
            new BN(this.content.facProof.w1, 16),
            new BN(this.content.facProof.w2, 16),
            new BN(this.content.facProof.v, 16)
        );
    }
}

export { KGRound2Message1 };