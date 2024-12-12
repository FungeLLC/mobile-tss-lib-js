import BN from 'bn.js';

class PartyID {
	public index: number;
	public moniker: string;

	constructor(index: number, moniker: string) {
		this.index = index;
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