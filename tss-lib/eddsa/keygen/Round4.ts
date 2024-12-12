import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import { BaseRound } from './Rounds';
import { ECPoint } from '../../crypto/ECPoint';
import BN from 'bn.js';

export class Round4 extends BaseRound implements Round {
	constructor(
		protected params: KeygenParams,
		protected data: LocalPartySaveData,
		protected temp: LocalTempData,
		protected out: (msg: MessageFromTss) => void,
		protected end: (data: LocalPartySaveData) => void,
	) {
		super(params, data, temp, out, end);
		this.number = 4;
	}

	public async start(): Promise<TssError | null> {
		try {
			if (this.started) {
				return new TssError('round already started');
			}
			this.started = true;
			this.resetOK();

			const i = this.params.partyID().index;
			const ecdsaPub = this.data.eddsaPub;

			if (!ecdsaPub) {
				return new TssError('ed25519 public key not set');
			}

			// Final key verification
			if (!this.verifyFinalKey()) {
				return new TssError('final key verification failed');
			}

			// End the protocol
			this.end(this.data);
			return null;

		} catch (error) {
			return new TssError(error instanceof Error ? error.message : String(error));
		}
	}

	private verifyFinalKey(): boolean {
		try {
			// Verify that our private share generates the expected public key
			const share = this.data.xi;
			if (!share) {
				return false;
			}

			// Generate public key point
			const pubKeyPoint = ECPoint.scalarBaseMult(
				this.params.ec.curve,
				share
			);

			// Point validation specific to Edwards curve
			if (!pubKeyPoint.isOnCurve()) {
				return false;
			}

			// Verify it matches the stored public key
			return this.data.eddsaPub?.equals(pubKeyPoint) ?? false;

		} catch (error) {
			console.error('Final key verification failed:', error);
			return false;
		}
	}

	public update(msg: ParsedMessage): [boolean, TssError | null] {
		// Round 4 doesn't expect any messages
		return [false, new TssError('unexpected message in round 4')];
	}
}

