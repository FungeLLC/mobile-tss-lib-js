import { PartyID } from '../../common/PartyID';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import { Parameters } from './interfaces';
import { CurveParams, RandomSource, KeygenConfig } from '../../common/Types';
import { curves } from 'elliptic';

class KeygenParams implements Parameters {
	public readonly totalParties: number;
	public readonly threshold: number;
	public readonly ec: EC & { n: BN };
	public readonly rand: RandomSource;
	
	public partyIDInstance: PartyID;
	public ecParams: CurveParams;
	public parties: PartyID[];

	constructor(config: KeygenConfig) {
		if (config.threshold > config.partyCount) {
			throw new Error('threshold must be less than or equal to party count');
		}
		this.totalParties = config.partyCount;
		this.threshold = config.threshold;

				// namespace PresetCurve {
				// 	interface Options {
				// 		type: string;
				// 		prime: string | null;
				// 		p: string;
				// 		a: string;
				// 		b: string;
				// 		n: string;
				// 		hash: any;
				// 		gRed: boolean;
				// 		g: any; // ?
				// 		beta?: string | undefined;
				// 		lambda?: string | undefined;
				// 		basis?: any; // ?
				// 	}
				// }

			// export interface CurveParams {
			// 	n: BN;        // Order of the curve
			// 	g: EC.KeyPair; // Generator point
			// 	curve: EC;    // Elliptic curve instance
			// 	p: BN;        // Field characteristic
			// }

		//create a new instance of the PresetCurve class using what we have in config.curve: CurveParams and filling in the missing values required by the constructor

		this.ecParams = config.curve;

		console.log('config.curve: ', config.curve);

		// const presetCurveParams = {
		// 	type: 'edwards',
		// 	prime: null,
		// 	p: config.curve.p.toString(16),
		// 	a: config.curve.curve.curve.a.toString(16),
		// 	c: config.curve.curve.curve.c.toString(16),
		// 	b: '52036cee2b6ffe73eca7f8b5c3b4f0d05d79483fbd2c42b2e9698e6ccb39abe9',
		// 	n: config.curve.n.toString(16),
		// 	hash: config.curve.curve.hash,
		// 	gRed: false,
		// 	g: [
		// 		config.curve.curve.g.getX().toString(16),
		// 		config.curve.curve.g.getY().toString(16)
		// 	],
		// 	curve: config.curve.curve
		// };

		// //create presetCurve instance
		// const presetCurve = new curves.PresetCurve(presetCurveParams);


		this.ec = new EC('ed25519') as EC & { n: BN };


		this.rand = config.randomSource;
		this.partyIDInstance = new PartyID(1, 'default');
		this.parties = new Array(this.totalParties);
		for (let i = 0; i < this.totalParties; i++) {
			this.parties[i] = new PartyID(i + 1, 'default');
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