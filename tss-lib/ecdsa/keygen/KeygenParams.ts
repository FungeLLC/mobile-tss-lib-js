import { PartyID } from '../../common/PartyID';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import { Parameters } from './interfaces';
import { CurveParams, RandomSource, KeygenConfig } from '../../common/Types';

class KeygenParams implements Parameters {
	public readonly totalParties: number;
	public readonly threshold: number;
	public readonly ec: EC & { n: BN };
	public readonly rand: RandomSource;
	public partyIDInstance: PartyID;
	public ecParams: CurveParams;

	public readonly noProofMod: boolean = false
	public readonly noProofFac: boolean = false
	parties: PartyID[];

	constructor(config: KeygenConfig) {
		if (config.threshold > config.partyCount) {
			throw new Error('threshold must be less than or equal to party count');
		}
		this.totalParties = config.partyCount;
		this.threshold = config.threshold;
		this.ec = new EC('secp256k1') as EC & { n: BN };

		this.rand = config.randomSource;
		this.partyIDInstance = new PartyID(1, 'default');
		this.ecParams = config.curve;
		this.parties = new Array(this.totalParties);
		for (let i = 0; i < this.totalParties; i++) {
			this.parties[i] = new PartyID(i + 1, 'default');
		}
	}

	partyCount(): number {
		return this.totalParties;
	}

	public partyID(): PartyID {
		return this.partyIDInstance;
	}
}

export { KeygenParams };