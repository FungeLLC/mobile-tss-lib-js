import { PartyID } from '../../common/PartyID';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import { Parameters } from './interfaces';
import { CurveParams, RandomSource, KeygenConfig } from '../../common/Types';

class KeygenParams implements Parameters {
	public readonly totalParties: number;
	public readonly threshold: number;
	public readonly ec: CurveParams;
	public readonly rand: RandomSource;
	private partyIDInstance: PartyID;
	private ecParams: {
		n: BN;
		g: any; // elliptic points are untyped in the library
		curve: EC;
		p: BN;
	};
	public readonly noProofMod: boolean = false
	public readonly noProofFac: boolean = false
	parties: PartyID[];

	constructor(config: KeygenConfig) {
		if (config.threshold > config.partyCount) {
			throw new Error('threshold must be less than or equal to party count');
		}
		this.totalParties = config.partyCount;
		this.threshold = config.threshold;
		this.ec = config.curve;
		this.rand = config.randomSource;
		this.partyIDInstance = new PartyID(0, 'default');
		this.ecParams = {
			n: new BN(0),
			g: null,
			curve: new EC('secp256k1'),
			p: new BN(0)
		};
		this.parties = new Array(this.totalParties);
		for (let i = 0; i < this.totalParties; i++) {
			this.parties[i] = new PartyID(i, 'default');
		}
	}

	partyCount(): number {
		throw new Error('Method not implemented.');
	}

	public partyID(): PartyID {
		return this.partyIDInstance;
	}
}

export { KeygenParams };