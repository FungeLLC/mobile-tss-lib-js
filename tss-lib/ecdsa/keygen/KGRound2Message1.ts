import { ParsedMessage, PartyID } from './interfaces';

class KGRound2Message1 implements ParsedMessage {
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
}

export { KGRound2Message1 };