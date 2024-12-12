import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { Commitment } from './interfaces';
import { KGRound1Message } from './Round1';
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

class Round2 implements Round {
    constructor(
        private params: KeygenParams,
        private data: LocalPartySaveData,
        private temp: LocalTempData,
        private out: (msg: MessageFromTss) => void,
        private end?: (data: LocalPartySaveData) => void
    ) { }

    canProceed(): boolean {
        const expKGRound2Messages1 = this.params.totalParties;
        const expKGRound2Messages2 = this.params.totalParties;
        const receivedR2Msgs1 = this.temp.kgRound2Message1s.filter(msg => msg !== undefined).length;
        const receivedR2Msgs2 = this.temp.kgRound2Message2s.filter(msg => msg !== undefined).length;
        return receivedR2Msgs1 === expKGRound2Messages1 && receivedR2Msgs2 === expKGRound2Messages2;
    }

    
    public begin(): void {
        const expKGRound2Messages1 = this.params.totalParties;
        const expKGRound2Messages2 = this.params.totalParties;

        const receivedR2Msgs1 = this.temp.kgRound2Message1s.filter(msg => msg !== undefined).length;
        const receivedR2Msgs2 = this.temp.kgRound2Message2s.filter(msg => msg !== undefined).length;

        if (receivedR2Msgs1 === expKGRound2Messages1 && receivedR2Msgs2 === expKGRound2Messages2) {
            this.endRound();
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

    

    public async start(): Promise<TssError | null> {
        try {
            if (this.temp.started) {
                return new TssError('round already started');
            }
            this.temp.started = true;

            const i = this.params.partyID().index;

            // 5. p2p send share ij to Pj
            const shares = this.temp.shares;
            for (let j = 0; j < this.params.totalParties; j++) {
                const Pj = this.params.parties[j];
                const r2msg1 = new KGRound2Message1(
                    Pj,
                    this.params.partyID(),
                    shares[j].share,
                    {} as ProofFac // No proof needed for EdDSA
                );

                if (j === i) {
                    this.temp.kgRound2Message1s[j] = r2msg1;
                    continue;
                }
                this.out(r2msg1);
            }

            // 7. BROADCAST de-commitments of Shamir poly*G
            const r2msg2 = new KGRound2Message2(
                this.params.partyID(),
                { deCommitPolyG: this.temp.deCommitPolyG }
            );
            this.temp.kgRound2Message2s[i] = r2msg2;
            this.out(r2msg2);

            return null;
        } catch (error) {
            return new TssError(error instanceof Error ? error.message : String(error));
        }
    }

    public update(msg: ParsedMessage): [boolean, TssError | null] {
        const fromPIdx = msg.getFrom().index;

        switch (msg.content().constructor.name) {
            case 'KGRound2Message1':
                this.temp.kgRound2Message1s[fromPIdx] = msg.content() as KGRound2Message1;
                break;
            case 'KGRound2Message2':
                this.temp.kgRound2Message2s[fromPIdx] = msg.content() as KGRound2Message2;
                break;
            default:
                return [false, new TssError(`unrecognised message type: ${msg.content().constructor.name}`)];
        }

        return [true, null];
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