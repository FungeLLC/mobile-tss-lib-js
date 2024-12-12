import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import { BaseRound } from './Rounds';
import { ECPoint } from '../../crypto/ECPoint';
import BN from 'bn.js';

class Round4 extends BaseRound implements Round {
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

	public canProceed(): boolean {
		if (!this.started) {
			return false;
		}
		return this.ok.every(ok => ok);
	}	

	public async start(): Promise<TssError | null> {
		try {
			if (this.started) {
				return new TssError('round already started');
			}
			this.started = true;
			this.resetOK();

			const i = this.params.partyID().index;
			const Ps = this.params.parties;
			const PIDs = Ps.map(p => p.keyInt());
			const ecdsaPub = this.data.ecdsaPub;

			if (!ecdsaPub) {
				return new TssError('ecdsa public key not set');
			}

			// 1-3. Verify Paillier proofs concurrently
			const verificationPromises = this.temp.kgRound3Messages.map(async (msg, j) => {
				if (j === i) {
					return true;
				}
				if (!msg) {
					return false;
				}

				const r3msg = msg.content();
				const proof = r3msg.unmarshalPaillierProof();
				const ppk = this.data.paillierPKs[j];

				if (!proof || !ppk) {
					console.warn(`paillier proof or public key missing for party ${j}`);
					return false;
				}

				try {
					return await proof.verify(
						ppk.N,
						PIDs[j],
						ecdsaPub
					);
				} catch (err) {
					console.warn(`paillier verify failed for party ${Ps[j]}: ${err}`);
					return false;
				}
			});

			// Wait for all verifications
			const results = await Promise.all(verificationPromises);

			// Process results
			const culprits: PartyID[] = [];
			results.forEach((ok, j) => {
				this.ok[j] = ok;
				if (!ok && j !== i) {
					culprits.push(Ps[j]);
				}
			});

			if (culprits.length > 0) {
				return new TssError(['paillier verify failed', culprits]);
			}

			// Final key assembly verification
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

			// Verify it matches the stored public key
			return this.data.ecdsaPub?.equals(pubKeyPoint) ?? false;

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

export { Round4 };