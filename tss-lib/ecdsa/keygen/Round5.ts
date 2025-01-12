import { MessageFromTss, ParsedMessage, Round, PartyID } from './interfaces';
import BN from 'bn.js';
import { BaseRound } from './Rounds';
import { TssError } from '../../common/TssError';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';

/**
 * Round5 is the final step in ECDSA key-gen, ensuring that the
 * local party has computed all necessary shares, and the public key
 * is fully set.
 */
export class Round5 extends BaseRound implements Round {
	public number = 5;

	constructor(
		protected params: KeygenParams,
		protected data: LocalPartySaveData,
		protected temp: LocalTempData,
		protected out: (msg: MessageFromTss) => void,
		protected end: (data: LocalPartySaveData) => void
	) {
		super(params, data, temp, out, end);
	}

	public async start(): Promise<TssError | null> {
		if (this.started) {
			return new TssError('round already started');
		}
		this.started = true;

		// Ensure final ecdsaPub is set
		if (!this.data.ecdsaPub) {
			return new TssError('ECDSA public key not finalized in Round5');
		}

		// Round complete
		this.end(this.data);
		return null;
	}

	public update(msg: ParsedMessage): [boolean, TssError | null] {
		// Round5 typically doesn't require more messages
		return [true, null];
	}
}