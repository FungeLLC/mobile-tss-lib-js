import { ParsedMessage, PartyID } from './interfaces';
import { MessageFromTss } from './interfaces';
import { PaillierProof } from '../../crypto/Paillier';

class KGRound3Message implements ParsedMessage, MessageFromTss {
	public from: PartyID;
	public content: any;
	wireBytes: Uint8Array;
	to?: PartyID | undefined;
	isBroadcast: boolean;

	constructor(from: PartyID, proof: PaillierProof) {
		this.from = from;
		this.content = {
			proof: JSON.stringify(proof),
		};
		// Serialize the content to wireBytes
		this.wireBytes = Buffer.from(JSON.stringify(this.content));
		this.isBroadcast = true;
	}

	public getFrom(): PartyID {
		return this.from;
	}

	public getContent(): any {
		return this.content;
	}

	public unmarshalPaillierProof(): PaillierProof {
		return PaillierProof.fromBytes(this.content.proof);
	}
}

export { KGRound3Message };