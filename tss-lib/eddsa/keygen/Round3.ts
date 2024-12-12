import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import { ECPoint } from '../../crypto/ECPoint';
import { PaillierProof } from '../../crypto/Paillier';

type Vs = ECPoint[];
import BN from 'bn.js';

class KGRound3Message implements ParsedMessage, MessageFromTss {
	public from: PartyID;
	public content: any;
	wireBytes: Uint8Array;
	to?: PartyID;
	isBroadcast: boolean;

	constructor(from: PartyID) {
		this.from = from;
		this.content = {};
		this.wireBytes = Buffer.from(JSON.stringify(this.content));
		this.isBroadcast = true;
	}

	public getFrom(): PartyID {
		return this.from;
	}

	public getContent(): any {
		return this.content;
	}

	public unmarshalPaillierProof(): PaillierProof {
		return PaillierProof.fromBytes(this.content.proof);
	}
}

class Round3 implements Round {
	private started: boolean = false;

	constructor(
		private params: KeygenParams,
		private data: LocalPartySaveData,
		private temp: LocalTempData,
		private out: (msg: MessageFromTss) => void,
		private end: (data: LocalPartySaveData) => void
	) { }
	canProceed(): boolean {
		for (let i = 0; i < this.params.totalParties; i++) {
			if (!this.temp.kgRound2Message1s[i]) return false;
		}
		return true;
	}
	public handleMessage(_msg: ParsedMessage): TssError | null {
		return null;
	}

	public isComplete(): boolean {
		if (!this.started) return false;
		for (let i = 0; i < this.params.totalParties; i++) {
			if (!this.temp.kgRound3Messages[i]) return false;
		}
		return true;
	}

	public async start(): Promise<TssError | null> {
		try {
			if (this.started) {
				return new TssError('round already started');
			}
			this.started = true;

			const PIdx = this.params.partyID().index;

			// Calculate xi by combining shares
			let xi = new BN(this.temp.shares[PIdx].share);
			for (let j = 0; j < this.params.totalParties; j++) {
				if (j === PIdx) continue;
				const r2msg1 = this.temp.kgRound2Message1s[j]?.content();
				if (!r2msg1) {
					return new TssError(`Missing share from party ${j}`);
				}
				const share = r2msg1.unmarshalShare();
				xi = xi.add(share).mod(this.params.ec.n);
			}
			this.data.xi = xi;

			// Process VSS
			const Vc: Vs = new Array(this.params.threshold + 1);
			for (let c = 0; c <= this.params.threshold; c++) {
				Vc[c] = this.temp.vs[c];
			}

			// Compute public key point
			const eddsaPub = Vc[0];
			this.data.eddsaPub = eddsaPub;

			// Broadcast completion message
			const msg = new KGRound3Message(this.params.partyID());
			this.temp.kgRound3Messages[PIdx] = msg;
			this.out(msg);

			return null;
		} catch (error) {
			return new TssError(error instanceof Error ? error.message : String(error));
		}
	}

	public update(msg: ParsedMessage): [boolean, TssError | null] {
		const fromPIdx = msg.getFrom().index;
		this.temp.kgRound3Messages[fromPIdx] = msg as KGRound3Message;
		return [true, null];
	}
}

export { Round3, KGRound3Message };