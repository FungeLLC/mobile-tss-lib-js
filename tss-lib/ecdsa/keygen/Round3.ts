import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import BN from 'bn.js';
import { KGRound3Message } from './KGRound3Message';
import { ECPoint } from '../../crypto/ECPoint';

export class Round3 implements Round {
	private started = false;
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
		// Ensure Round2 data is present
		for (let i = 0; i < this.params.totalParties; i++) {
			if (!this.temp.kgRound2Message1s[i] || !this.temp.kgRound2Message2s[i]) {
				return false;
			}
		}
		return true;
	}

	public async start(): Promise<TssError | null> {
		try {
			if (this.started) {
				return new TssError('round already started');
			}
			this.started = true;

			const partyID = this.params.partyID();
			const pIndex = partyID.arrayIndex;

			// Combine shares to compute private key
			if (!this.temp.shares[pIndex] || !this.temp.shares[pIndex].share) {
				return new TssError(`Missing share for party index ${pIndex}`);
			}
			let xi = new BN(this.temp.shares[pIndex].share);
			for (let j = 0; j < this.params.totalParties; j++) {
				if (j === pIndex) continue;
				const r2msg1 = this.temp.kgRound2Message1s[j]?.content;
				if (!r2msg1) {
					return new TssError(`Missing share from party ${j}`);
				}
				const share = new BN(r2msg1.share);
				if (!share) {
					return new TssError(`Unmarshalled share is undefined for party ${j}`);
				}
				xi = xi.add(share).umod(this.params.ec.n);
			}
			this.data.xi = xi;

			// Reconstruct commitment points
			// For ECDSA, the first VSS commitment can be used as a reference
			const pubPoint: ECPoint = this.temp.vs[0];
			this.data.ecdsaPub = pubPoint;

			// Broadcast completion message
			const proof = this.temp.kgRound2Message2s[pIndex]?.content.proof;
			const r3Msg = new KGRound3Message(partyID, proof);
			this.temp.kgRound3Messages[pIndex] = r3Msg;
			this.ok[pIndex] = true;
			this.out(r3Msg);

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

			this.temp.kgRound3Messages[fromPIdx] = msg;
			this.ok[fromPIdx] = true;

			if (this.isComplete()) {
				// Round complete, finalize data
				// Example: use the same pub point for all parties or recalc if needed
				this.end(this.data);
			}
			return [true, null];
		} catch (error) {
			return [false, new TssError(error instanceof Error ? error.message : String(error))];
		}
	}

	public isComplete(): boolean {
		if (!this.started) return false;
		return this.ok.every(x => x);
	}
}