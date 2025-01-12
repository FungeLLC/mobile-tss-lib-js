import { MessageFromTss, ParsedMessage, PartyID } from './interfaces';

export class KGRound4Message implements ParsedMessage, MessageFromTss {
	public isBroadcast: boolean;
	public wireBytes: Uint8Array;
	public from: PartyID;
	public to?: PartyID;

	constructor(private partyID: PartyID) {
		this.isBroadcast = true;
		this.wireBytes = new Uint8Array();
		this.from = partyID;
	}

	public getFrom(): PartyID {
		return this.partyID;
	}

	public content(): any {
		return {};
	}

	public toWire(): Buffer {
		return Buffer.from([]);
	}
}