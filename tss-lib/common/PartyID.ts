import BN from 'bn.js';

class PartyID {
	public index: number;
	public arrayIndex: number;
	public moniker: string;

	constructor(index: number, moniker: string) {
		this.index = index;
		this.arrayIndex = index - 1;
		this.moniker = moniker;
	}

	public keyInt(): BN {

		return new BN(this.index);

	}



	public toString(): string {

		return this.index.toString();

	}

}

export { PartyID };