import { PartyID } from './PartyID';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import { Parameters } from './interfaces';

class KeygenParams implements Parameters {
	public totalParties: number;
	public partyThreshold: number;
	private partyIDInstance: PartyID;
	private ecParams: {
		n: BN;
		g: any; // elliptic points are untyped in the library
		curve: EC;
		p: BN;
	};
	private randSource: any;
	public readonly noProofMod: boolean = false
	public readonly noProofFac: boolean = false
	threshold: number;
	parties: PartyID[];

	constructor(
		totalParties: number,
		ecParams: { n: BN; g: any; curve: EC; p: BN },
		partyThreshold: number,
		randSource?: any,
		partyIDInstance: PartyID = new PartyID(0, 'default')
	) {
		this.totalParties = totalParties;
		this.partyIDInstance = partyIDInstance;
		this.ecParams = ecParams;
		this.partyThreshold = partyThreshold;
		this.randSource = randSource;
		this.threshold = partyThreshold;
		this.parties = new Array(totalParties);
		for (let i = 0; i < totalParties; i++) {
			this.parties[i] = new PartyID(i, 'default');
		}
	}

	partyCount(): number {
		throw new Error('Method not implemented.');
	}

	public partyID(): PartyID {
		return this.partyIDInstance;
	}

	public get ec() {
		return this.ecParams;
	}

	public get rand() {
		return this.randSource;
	}
}

export { KeygenParams };