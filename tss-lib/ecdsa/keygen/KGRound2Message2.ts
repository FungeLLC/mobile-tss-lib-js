import { MessageFromTss, ParsedMessage, PartyID } from './interfaces';
import BN from 'bn.js';

class KGRound2Message2 implements MessageFromTss {
    public from: PartyID;
    public content: any;
	public wireBytes: Buffer;
	public isBroadcast: boolean;

    constructor(from: PartyID, content: any) {
        this.from = from;
        this.content = content;
		this.wireBytes = Buffer.from(''); // Initialize wireBytes appropriately
		this.isBroadcast = true; // Set isBroadcast to true or false as needed

    }

    public getFrom(): PartyID {
        return this.from;
    }

    public getContent(): any {
        return this.content;
    }

    public unmarshalDeCommitPolyG(): any {
        // Assuming DeCommitPolyG is an object with properties that are hex strings
        return this.content.deCommitPolyG.map((item: string) => new BN(item, 16));
    }

    public unmarshalModProof(): any {
        // Assuming ModProof is an object with properties that are hex strings
        return {
            w: new BN(this.content.modProof.w, 16),
            x: this.content.modProof.x.map((item: string) => new BN(item, 16)),
            a: new BN(this.content.modProof.a, 16),
            b: new BN(this.content.modProof.b, 16),
            z: this.content.modProof.z.map((item: string) => new BN(item, 16))
        };
    }
}

export { KGRound2Message2 };