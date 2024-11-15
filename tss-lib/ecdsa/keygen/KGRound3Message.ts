import { ParsedMessage, PartyID } from './interfaces';
import { MessageFromTss } from './interfaces';

class KGRound3Message implements ParsedMessage, MessageFromTss {
	public from: PartyID;
	public content: any;
	wireBytes: Uint8Array;
	to?: PartyID | undefined;
	isBroadcast: boolean;

	constructor(from: PartyID, content: any) {
		this.from = from;
		this.content = content;
		this.wireBytes = new Uint8Array(); // Initialize wireBytes appropriately
		this.isBroadcast = true; // Set isBroadcast to true or false as needed
		
	}

	public getFrom(): PartyID {
		return this.from;
	}

	public getContent(): any {
		return this.content;
	}
}

export { KGRound3Message };