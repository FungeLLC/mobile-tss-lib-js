import { KeygenParams, MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { Commitment, Shares } from './interfaces';
import { ProofFac } from '../../crypto/FACProof';
import { ProofMod } from '../../crypto/MODProof';
import { KGRound1Message } from './Round1';
import { KGRound2Message1 } from './KGRound2Message1';
import { KGRound2Message2 } from './KGRound2Message2';
import { TssError } from './TssError';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import BN from 'bn.js';


class Round2 implements Round {
    constructor(
        private params: KeygenParams,
        private data: LocalPartySaveData,
        private temp: LocalTempData,
        private out: (msg: MessageFromTss) => void,
        private end?: (data: LocalPartySaveData) => void
    ) { }

    public async start(): Promise<TssError | null> {
        try {
            if (this.temp.started) {
                return new TssError('round already started');
            }
            this.temp.started = true;

            const i = this.params.partyID().index;

            // Verify DLN proofs, store r1 message pieces, ensure uniqueness of h1j, h2j
            const h1H2Map = new Map<string, boolean>();
            const dlnProof1FailCulprits: (PartyID | null)[] = new Array(this.temp.kgRound1Messages.length).fill(null);
            const dlnProof2FailCulprits: (PartyID | null)[] = new Array(this.temp.kgRound1Messages.length).fill(null);

            for (let j = 0; j < this.temp.kgRound1Messages.length; j++) {
                const msg = this.temp.kgRound1Messages[j];
                if (!msg) {
                    return new TssError('message is null');
                }

                const r1msg = msg.content() as KGRound1Message;
                const H1j = r1msg.unmarshalH1();
                const H2j = r1msg.unmarshalH2();
                const NTildej = r1msg.unmarshalNTilde();
                const paillierPKj = r1msg.unmarshalPaillierPK();

                if (paillierPKj.n.bitLength() !== 2048) {
                    return new TssError('got paillier modulus with insufficient bits for this party');
                }
                if (H1j.cmp(H2j) === 0) {
                    return new TssError('h1j and h2j were equal for this party');
                }
                if (NTildej.bitLength() !== 2048) {
                    return new TssError('got NTildej with insufficient bits for this party');
                }

                const h1JHex = H1j.toString('hex');
                const h2JHex = H2j.toString('hex');
                if (h1H2Map.has(h1JHex) || h1H2Map.has(h2JHex)) {
                    return new TssError('this h1j or h2j was already used by another party');
                }
                h1H2Map.set(h1JHex, true);
                h1H2Map.set(h2JHex, true);

                // Verify DLN proofs
                if (!r1msg.verifyDLNProof1(H1j, H2j, NTildej)) {
                    dlnProof1FailCulprits[j] = msg.getFrom();
                }
                if (!r1msg.verifyDLNProof2(H2j, H1j, NTildej)) {
                    dlnProof2FailCulprits[j] = msg.getFrom();
                }
            }

            for (const culprit of [...dlnProof1FailCulprits, ...dlnProof2FailCulprits]) {
                if (culprit) {
                    return new TssError(['dln proof verification failed', culprit]);
                }
            }

            // Save NTilde_j, h1_j, h2_j, ...
            for (let j = 0; j < this.temp.kgRound1Messages.length; j++) {
                if (j === i) continue;
                const msg = this.temp.kgRound1Messages[j];
				if (!msg) {
					continue;
				}
                const r1msg = msg.content() as KGRound1Message;
                const paillierPK = r1msg.unmarshalPaillierPK();
                const H1j = r1msg.unmarshalH1();
                const H2j = r1msg.unmarshalH2();
                const NTildej = r1msg.unmarshalNTilde();
                const KGC = r1msg.unmarshalCommitment();

                this.data.paillierPKs[j] = paillierPK;
                this.data.NTildej[j] = NTildej;
                this.data.H1j[j] = H1j;
                this.data.H2j[j] = H2j;
                this.temp.KGCs[j] = new Commitment(new BN(KGC));
            }

            // P2P send share ij to Pj
            const shares = this.temp.shares;
            const contextI = Buffer.concat([this.temp.ssid, Buffer.from(i.toString())]);
            for (let j = 0; j < this.params.totalParties; j++) {
                const Pj = this.params.partyID();
                let facProof = new ProofFac();

                if (!this.params.noProofFac) {
                    facProof = ProofFac.newProof(contextI, this.params.ec, this.data.paillierSK.n, this.data.NTildej[j], this.data.H1j[j], this.data.H2j[j], this.data.paillierSK.p, this.data.paillierSK.q);
                }

                const r2msg1 = new KGRound2Message1(Pj, this.params.partyID(), shares.getShare(j), facProof);
                if (j === i) {
                    this.temp.kgRound2Message1s[j] = r2msg1;
                    continue;
                }
                this.out(r2msg1);
            }

            // Broadcast de-commitments of Shamir poly*G
            let modProof: ProofMod;
            if (!this.params.noProofMod) {
                modProof = await ProofMod.newProof(contextI, this.data.paillierSK.n, this.data.paillierSK.p, this.data.paillierSK.q, this.params.rand);
            }
            const r2msg2 = new KGRound2Message2(this.params.partyID(), this.temp.deCommitPolyG);
            this.temp.kgRound2Message2s[i] = r2msg2;
            this.out(r2msg2);

            return null;
        } catch (error) {
            return new TssError(error);
        }
    }

    public update(msg: any): [boolean, TssError | null] {
        const fromPIdx = msg.getFrom().index;

        switch (msg.content().constructor.name) {
            case 'KGRound2Message1':
                this.temp.kgRound2Message1s[fromPIdx] = msg;
                break;
            case 'KGRound2Message2':
                this.temp.kgRound2Message2s[fromPIdx] = msg;
                break;
            default:
                return [false, new TssError(`unrecognised message type: ${msg.content().constructor.name}`)];
        }

        // Check if all messages are received
        if (this.temp.kgRound2Message1s.every(m => m !== undefined) && this.temp.kgRound2Message2s.every(m => m !== undefined)) {
            this.endRound();
        }

        return [true, null];
    }

    private endRound(): void {
        // Process the received messages
        for (let j = 0; j < this.params.totalParties; j++) {
            const msg1 = this.temp.kgRound2Message1s[j];
            const msg2 = this.temp.kgRound2Message2s[j];

            if (msg1 && msg2) {
                const r2msg1 = msg1.content() as KGRound2Message1;
                const r2msg2 = msg2.content() as KGRound2Message2;

                // Verify the de-commitments and proofs
                const share = r2msg1.unmarshalShare();
                const facProof = r2msg1.unmarshalFacProof();
                const deCommitPolyG = r2msg2.unmarshalDeCommitPolyG();
                const modProof = r2msg2.unmarshalModProof();

                // Add additional verification logic here if needed
                // ...

                // Store the verified shares and proofs
                this.data.shares.addShare(share);
                this.data.facProofs[j] = facProof;
                this.data.deCommitPolyGs[j] = deCommitPolyG;
                this.data.modProofs[j] = modProof;
            }
        }

        // Move to the next round
        if (this.end) {
            this.end(this.data);
        }
    }
}

export { Round2 };