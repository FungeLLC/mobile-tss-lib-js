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
	private ok: boolean[];
	public number = 3;

	constructor(
		private params: KeygenParams,
		private data: LocalPartySaveData,
		private temp: LocalTempData,
		private out: (msg: MessageFromTss) => void,
		private end: (data: LocalPartySaveData) => void
	) {
		this.ok = new Array(params.totalParties).fill(false);
	}

	public canProceed(): boolean {
		// Check Round2 messages are present
		for (let i = 0; i < this.params.totalParties; i++) {
			if (!this.temp.kgRound2Message1s[i] || !this.temp.kgRound2Message2s[i]) {
				return false;
			}
		}
		return true;
	}

	public handleMessage(_msg: ParsedMessage): TssError | null {
		return null;
	}

	public async start(): Promise<TssError | null> {
		try {
			if (this.started) {
				return new TssError('round already started');
			}
			this.started = true;

			const partyID = this.params.partyID();
			const arrayIdx = partyID.arrayIndex;

			// Calculate xi by combining shares
			let xi = new BN(this.temp.shares[arrayIdx].share);
			for (let j = 0; j < this.params.totalParties; j++) {
				if (j === arrayIdx) continue;
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
			const msg = new KGRound3Message(partyID);
			this.temp.kgRound3Messages[arrayIdx] = msg;
			this.ok[arrayIdx] = true;
			this.out(msg);

			return null;
		} catch (error) {
			return new TssError(error instanceof Error ? error.message : String(error));
		}
	}

	public update(msg: ParsedMessage): [boolean, TssError | null] {
		try {
			const fromParty = msg.getFrom();
			const fromPIdx = fromParty.arrayIndex;
			
			if (fromPIdx < 0 || fromPIdx >= this.params.totalParties) {
				return [false, new TssError('invalid party array index')];
			}

			if (this.ok[fromPIdx]) {
				return [false, new TssError('duplicate message')];
			}

			this.temp.kgRound3Messages[fromPIdx] = msg as KGRound3Message;
			this.ok[fromPIdx] = true;

			if (this.isComplete()) {
				this.data.eddsaPub = this.temp.vs[0];
				this.end(this.data);
			}

			return [true, null];
		} catch (err) {
			return [false, new TssError(err instanceof Error ? err.message : String(err))];
		}
	}

	public isComplete(): boolean {
		if (!this.started) return false;
		return this.ok.every(v => v);
	}
}

export { Round3, KGRound3Message };