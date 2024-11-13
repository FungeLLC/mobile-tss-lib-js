import { PartyID } from './PartyID';

class KeygenParams {
	public totalParties: number;
	private partyIDInstance: PartyID;

	constructor(totalParties: number, partyIDInstance: PartyID) {
		this.totalParties = totalParties;
		this.partyIDInstance = partyIDInstance;
	}

	public partyID(): PartyID {
		return this.partyIDInstance;
	}
}

export { KeygenParams };