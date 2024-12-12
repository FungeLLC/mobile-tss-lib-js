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
			n: new BN('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 16), // Ed25519 order
			g: null,
			curve: new EC('ed25519'),
			p: new BN('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', 16)  // Ed25519 prime
		};
		this.parties = new Array(this.totalParties);
		for (let i = 0; i < this.totalParties; i++) {
			this.parties[i] = new PartyID(i, 'default');
		}
	}

	public partyCount(): number {
		return this.totalParties;
	}

	public partyID(): PartyID {
		return this.partyIDInstance;
	}
}

export { KeygenParams };