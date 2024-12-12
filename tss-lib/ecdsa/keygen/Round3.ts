import { MessageFromTss, Round, ParsedMessage, PartyID, Commitment } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import ModInt from '../../common/ModInt';
import { ECPoint } from '../../crypto/ECPoint';
import {  Share } from '../../crypto/VSS';
import { HashCommitDecommit } from '../../crypto/Commitment';
type Vs = ECPoint[];
import BN from 'bn.js';
import { KGRound3Message } from './KGRound3Message';

class Round3 implements Round {
	private started: boolean = false;

	constructor(
		private params: KeygenParams,
		private data: LocalPartySaveData,
		private temp: LocalTempData,
		private out: (msg: MessageFromTss) => void,
		private end: (data: LocalPartySaveData) => void
	) { }

	public canProceed(): boolean {
		if (!this.started) return false;
		for (let i = 0; i < this.params.totalParties; i++) {
			if (i === this.params.partyID().index) continue;
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

			// 1,9. Calculate xi by combining shares
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

			// 2-3. Process VSS
			const Vc: Vs = new Array(this.params.threshold + 1);
			for (let c = 0; c <= this.params.threshold; c++) {
				Vc[c] = this.temp.vs[c];
			}

			// 4-11. Verify commitments and VSS shares
			const verificationPromises = Array.from(
				{ length: this.params.totalParties },
				async (_, j) => {
					if (j === PIdx) return null;
					return this.verifyPartyData(j);
				}
			);

			const results = await Promise.all(verificationPromises);
			const errors = results
				.filter((r): r is { error: string } => r !== null && r.error !== undefined)
				.map(r => r.error);

			if (errors.length > 0) {
				return new TssError(errors.join(', '));
			}

			// 12-16. Compute Xj for each Pj
			const modQ = new ModInt(this.params.ec.n);
			this.data.bigXj = new Array(this.params.totalParties);

			for (let j = 0; j < this.params.totalParties; j++) {
				const kj = this.params.parties[j].keyInt();
				let BigXj = Vc[0];
				let z = new BN(1);

				for (let c = 1; c <= this.params.threshold; c++) {
					z = modQ.mul(z, kj) as BN;
					BigXj = BigXj.add(Vc[c].scalarMult(z));
				}
				this.data.bigXj[j] = BigXj;
			}

			// 17. Compute and save ECDSA public key
			const ecdsaPubKey = Vc[0];
			this.data.ecdsaPub = ecdsaPubKey;

			// Generate and broadcast Paillier proof
			const ki = this.params.partyID().keyInt();
			const proof = this.data.paillierSK.generateProof(ki, ecdsaPubKey);
			const r3msg = new KGRound3Message(this.params.partyID(), proof);
			this.temp.kgRound3Messages[PIdx] = r3msg;
			this.out({
				wireBytes: Buffer.from(JSON.stringify(r3msg.content())),
				from: this.params.partyID(),
				isBroadcast: true
			});

			return null;
		} catch (error) {
			return new TssError(error instanceof Error ? error.message : String(error));
		}
	}

	private async verifyPartyData(j: number): Promise<{ error?: string }> {
		try {
			const r2msg2 = this.temp.kgRound2Message2s[j]?.content();
			if (!r2msg2) {
				return { error: `party ${j}: kgRound2Message2s is null` };
			}

			// Verify commitment and get points
			const KGCj = this.temp.KGCs[j];
			if (!KGCj) {
				return { error: `party ${j}: KGC data is null` };
			}

			const decommitment = r2msg2.unmarshalDeCommitment();
			const cmtDeCmt = new HashCommitDecommit(KGCj.value, decommitment);
			const [ok, flatPolyGs] = cmtDeCmt.deCommit();

			if (!ok || !flatPolyGs) {
				return { error: `party ${j}: de-commitment verify failed` };
			}

			// Verify VSS
			const PjVs = ECPoint.unFlattenECPoints(flatPolyGs, this.params.ec.curve);
			const r2msg1 = this.temp.kgRound2Message1s[j]?.content();
			if (!r2msg1) {
				return { error: `party ${j}: kgRound2Message1s is null` };
			}

			const share = r2msg1.unmarshalShare();
			if (!new Share(
				this.params.threshold,
				this.params.partyID().keyInt(),
				share
			).verify(this.params.ec.curve, this.params.threshold, PjVs)) {
				return { error: `party ${j}: vss verify failed` };
			}

			return {};
		} catch (error) {
			return { error: `party ${j}: ${error instanceof Error ? error.message : String(error)}` };
		}
	}

	public update(msg: ParsedMessage): [boolean, TssError | null] {
		const fromPIdx = msg.getFrom().index;

		if (!(msg.content() instanceof KGRound3Message)) {
			return [false, new TssError(`unrecognised message type: ${msg.content().constructor.name}`)];
		}

		this.temp.kgRound3Messages[fromPIdx] = msg;

		return [true, null];
	}
}

export { Round3 };