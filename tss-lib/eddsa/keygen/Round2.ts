import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { Commitment } from './interfaces';
import { BaseRound } from './Rounds';
import { KGRound2Message1 } from './KGRound2Message1';
import { KGRound2Message2 } from './KGRound2Message2';
import { TssError } from '../../common/TssError';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import BN from 'bn.js';
import { HashCommitDecommit } from '../../crypto/Commitment';
import { ECPoint } from '../../crypto/ECPoint';
import { KeygenParams } from './KeygenParams';
import { Share } from '../../crypto/VSS';
import { ProofFac } from '../../crypto/FACProof';

class Round2 extends BaseRound implements Round {
    public number = 2;
    private ok1: boolean[];
    private ok2: boolean[];

    constructor(
        protected params: KeygenParams,
        protected data: LocalPartySaveData,
        protected temp: LocalTempData,
        protected out: (msg: MessageFromTss) => void,
        protected end: (data: LocalPartySaveData) => void,
    ) {
        super(params, data, temp, out, end);
        this.ok1 = new Array(params.totalParties).fill(false);
        this.ok2 = new Array(params.totalParties).fill(false);
    }

    public canProceed(): boolean {
        const allOk1 = this.ok1.every(v => v);
        const allOk2 = this.ok2.every(v => v);
        return allOk1 && allOk2 && this.started;
    }

    public async start(): Promise<TssError | null> {
        try {
            if (this.started) {
                return new TssError('round already started');
            }
            this.started = true;

            const partyID = this.params.partyID();
            const arrayIdx = partyID.arrayIndex;

            // Share sending
            for (let j = 0; j < this.params.totalParties; j++) {
                const Pj = this.params.parties[j];

                if (!this.temp.shares || !this.temp.shares[j]) {
                    throw new TssError(`missing share for party ${j}`);
                }

                const r2msg1 = new KGRound2Message1(
                    partyID,
                    Pj,
                    this.temp.shares[j].share,
                    {} as ProofFac // No proof needed for EdDSA
                );

                if (j === arrayIdx) {
                    // Store own message
                    this.temp.kgRound2Message1s[j] = r2msg1;
                    this.ok1[j] = true;
                    continue;
                }
                // Send to other parties
                this.out(r2msg1);
            }

            // Broadcast decommitment
            const r2msg2 = new KGRound2Message2(
                partyID,
                { deCommitPolyG: this.temp.deCommitPolyG }
            );
            this.temp.kgRound2Message2s[arrayIdx] = r2msg2;
            this.ok2[arrayIdx] = true;
            this.out(r2msg2);

            return null;
        } catch (error) {
            return new TssError(error instanceof Error ? error.message : String(error));
        }
    }

    public update(msg: ParsedMessage): [boolean, TssError | null] {
        try {
            const fromParty = msg.getFrom();
            const fromPIdx = fromParty.arrayIndex;

            // Validate sender's array index
            if (fromPIdx < 0 || fromPIdx >= this.params.totalParties) {
                return [false, new TssError('invalid party array index')];
            }

            if (fromPIdx !== this.params.partyID().arrayIndex) {
                // Handle message based on type
                if (msg instanceof KGRound2Message1) {

                    if (this.ok1[fromPIdx]) {
                        return [false, new TssError('duplicate Round2Message1')];
                    }
                    this.temp.kgRound2Message1s[fromPIdx] = msg;
                    this.ok1[fromPIdx] = true;
                } else if (msg instanceof KGRound2Message2) {

                    if (this.ok2[fromPIdx]) {
                        return [false, new TssError('duplicate Round2Message2')];
                    }
                    this.temp.kgRound2Message2s[fromPIdx] = msg;
                    this.ok2[fromPIdx] = true;
                } else {
                    return [false, new TssError('unrecognized Round2 message')];
                }

                    // Check if round complete
                    if (this.canProceed()) {
                        this.end(this.data);
                    }
                }

            return [true, null];
        } catch (err) {
            return [false, new TssError(err instanceof Error ? err.message : String(err))];
        }
    }

    public handleMessage(msg: ParsedMessage): void {
        const [success, error] = this.update(msg);
        if (error) {
            throw error;
        }
        if (success) {
            this.begin();
        }
    }

    private begin(): void {
        if (this.canProceed()) {
            this.endRound();
        }
    }

    private endRound(): void {
        // Process the received messages
        for (let j = 0; j < this.params.totalParties; j++) {
            const msg1 = this.temp.kgRound2Message1s[j];
            const msg2 = this.temp.kgRound2Message2s[j];

            if (!msg1 || !msg2) {
                throw new TssError(`Missing message from party ${j}`);
            }

            const r2msg1 = msg1.content() as KGRound2Message1;
            const r2msg2 = msg2.content() as KGRound2Message2;

            // 1. Verify Commitment
            const KGCj = this.temp.KGCs[j];
            if (!KGCj) {
                throw new TssError(`Missing commitment from party ${j}`);
            }

            const decommitment = r2msg2.unmarshalDeCommitPolyG();
            const cmtDeCmt = new HashCommitDecommit(KGCj.value, decommitment);
            const [ok, flatPolyGs] = cmtDeCmt.deCommit();

            if (!ok || !flatPolyGs) {
                throw new TssError(`De-commitment verification failed for party ${j}`);
            }

            // 2. Verify VSS
            const PjVs = ECPoint.unFlattenECPoints(flatPolyGs, this.params.ec.curve);
            const share = r2msg1.unmarshalShare();
            const PjShare = new Share(
                this.params.threshold,
                this.params.partyID().keyInt(),
                share
            );

            if (!PjShare.verify(this.params.ec.curve, this.params.threshold, PjVs)) {
                throw new TssError(`VSS verification failed for party ${j}`);
            }
        }

        // Move to next round
        if (this.end) {
            this.end(this.data);
        }
    }
}

export { Round2 };