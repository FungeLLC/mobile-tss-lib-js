import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { BaseRound } from './Rounds';
import { KGRound2Message1 } from './KGRound2Message1';
import { KGRound2Message2 } from './KGRound2Message2';
import { TssError } from '../../common/TssError';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { HashCommitDecommit } from '../../crypto/Commitment';
import { ECPoint } from '../../crypto/ECPoint';
import { KeygenParams } from './KeygenParams';
import { Share } from '../../crypto/VSS';
import { ProofFac } from '../../crypto/FACProof';
import BN from 'bn.js';
import crypto from 'crypto';

export class Round2 extends BaseRound implements Round {
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

            // Distribute each share to the corresponding party
            for (let j = 0; j < this.params.totalParties; j++) {
                const Pj = this.params.parties[j];

                if (!this.temp.shares || !this.temp.shares[j]) {
                    throw new TssError(`missing share for party ${j}`);
                }

                // For ECDSA, create a FAC proof (Feldman-And-Carmichael) for the share
                const proof = this.createProofFac(this.temp.shares[j]);

                const r2msg1 = new KGRound2Message1(
                    partyID,
                    Pj,
                    this.temp.shares[j].share,
                    proof
                );

                if (j === arrayIdx) {
                    this.temp.kgRound2Message1s[j] = r2msg1;
                    this.ok1[j] = true;
                    continue;
                }
                // Send share & proof to other parties
                this.out(r2msg1);
            }

            // Broadcast our decommitment for the polynomial commitments
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

            if (fromPIdx < 0 || fromPIdx >= this.params.totalParties) {
                return [false, new TssError('invalid party array index')];
            }

            // Skip self-sent messages
            if (fromPIdx === this.params.partyID().arrayIndex) {
                return [true, null];
            }

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
                return [false, new TssError('unrecognized Round2 message type')];
            }

            // If we have everyone's messages, we can finalize
            if (this.canProceed()) {
                this.end(this.data);
            }
            return [true, null];
        } catch (err) {
            return [false, new TssError(err instanceof Error ? err.message : String(err))];
        }
    }

    private createProofFac(share: Share): ProofFac {
        if (!share || !share.id || !share.share) {
            throw new TssError('invalid share for FAC proof');
        }

        const ec = this.params.ec;
        const x = share.id;
        const y = share.share;
        const rand = new BN(crypto.randomBytes(32)).umod(ec.n);

        // Build a generator point from the curve
        const G = new ECPoint(ec, ec.g.getX(), ec.g.getY());
        const A = G.mul(rand);

        // Challenge
        const challengeInput = Buffer.concat([
            x.toBuffer('be', 32),
            y.toBuffer('be', 32),
            A.X().toBuffer('be', 32),
            A.Y().toBuffer('be', 32)
        ]);
        const c = new BN(crypto.createHash('sha256').update(challengeInput).digest()).umod(ec.n);

        // z = rand + c * y
        const z = rand.add(c.mul(y)).umod(ec.n);

        // Use the simpler ECDSA constructor
        return ProofFac.fromEcdsaParams(A.X(), A.Y(), x, y, z);
    }
}