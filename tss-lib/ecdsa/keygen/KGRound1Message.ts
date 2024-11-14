import { ParsedMessage, PartyID } from './interfaces';
import BN from 'bn.js';
import { DLNProof } from '../../crypto/crypto'; // Assuming DLNProof is a class that handles DLN proof verification

class KGRound1Message implements ParsedMessage {
    private from: PartyID;
    public content: any;

    constructor(from: PartyID, content: any) {
        this.from = from;
        this.content = content;
    }

    public getFrom(): PartyID {
        return this.from;
    }

    public getContent(): any {
        return this.content;
    }

    public unmarshalH1(): BN {
        return new BN(this.content.h1, 16);
    }

    public unmarshalH2(): BN {
        return new BN(this.content.h2, 16);
    }

    public unmarshalNTilde(): BN {
        return new BN(this.content.nTilde, 16);
    }

    public unmarshalPaillierPK(): any {
        // Assuming PaillierPK is an object with a property 'n' which is a hex string
        return {
            n: new BN(this.content.paillierPK.n, 16)
        };
    }

    public unmarshalCommitment(): any {
        // Assuming Commitment is an object with a property 'c' which is a hex string
        return {
            c: new BN(this.content.commitment.c, 16)
        };
    }

    public verifyDLNProof1(H1j: BN, H2j: BN, NTildej: BN): boolean {
        // Implement the logic to verify DLN proof 1
        const dlnProof = new DLNProof(this.content.dlnProof1.alpha, this.content.dlnProof1.t);
        return dlnProof.verify(H1j, H2j, NTildej);
    }

    public verifyDLNProof2(H2j: BN, H1j: BN, NTildej: BN): boolean {
        // Implement the logic to verify DLN proof 2
        const dlnProof = new DLNProof(this.content.dlnProof2.alpha, this.content.dlnProof2.t);
        return dlnProof.verify(H2j, H1j, NTildej);
    }
}

export { KGRound1Message };