import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from './TssError';
import { BaseRound } from './Rounds';

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

	public async start(): Promise<TssError | null> {
		try {
			if (this.started) {
				return new TssError('round already started');
			}
			this.number = 4;
			this.started = true;
			this.resetOK();

			const i = this.params.partyID().index;
			const Ps = this.params.parties;
			const PIDs = Ps.map(p => p.keyInt());
			const ecdsaPub = this.data.ecdsaPub;

			// 1-3. Verify Paillier proofs concurrently
			const verificationPromises = this.temp.kgRound3Messages.map(async (msg, j) => {
				if (j === i) {
					return true;
				}
				if (!msg) {
					return false;
				}

				const r3msg = msg.content();
				const proof = r3msg.unmarshalProofInts();
				const ppk = this.data.paillierPKs[j];

				try {
					return await proof.verify(ppk.n, PIDs[j], ecdsaPub);
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
					console.warn(`paillier verify failed for party ${Ps[j]}`);
				} else {
					console.debug(`paillier verify passed for party ${Ps[j]}`);
				}
			});

			if (culprits.length > 0) {
				return new TssError(['paillier verify failed', culprits]);
			}

			// End the round
			this.end(this.data);
			return null;

		} catch (error) {
			return new TssError(error instanceof Error ? error.message : String(error));
		}
	}

	public update(msg: ParsedMessage): [boolean, TssError | null] {
		// Not expecting any incoming messages in this round
		return [false, null];
	}
}

export { Round4 };