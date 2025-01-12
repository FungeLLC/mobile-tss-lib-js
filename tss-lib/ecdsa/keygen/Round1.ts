import { Message, Round, ParsedMessage, PartyID, MessageFromTss } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import { BaseRound } from './Rounds';
import { HashCommitment } from '../../crypto/Commitment';
import { Create } from '../../crypto/VSS';
import { ECPoint } from '../../crypto/ECPoint';
import { getRandomPositiveInt } from '../../common/Random';
import BN from 'bn.js';
import * as crypto from 'crypto';

/**
 * KGRound1Message is the broadcast message containing the commitment data
 * for ECDSA Round1. 
 */
export class KGRound1Message implements ParsedMessage, MessageFromTss {
    public isBroadcast: boolean;
    public wireBytes: Uint8Array;
    from: PartyID;
    to?: PartyID;

    constructor(
        private partyID: PartyID,
        private commitment: Buffer,
    ) {
        this.isBroadcast = true;
        this.wireBytes = new Uint8Array(this.commitment);
        this.from = partyID;
    }

    public getFrom(): PartyID {
        return this.partyID;
    }

    public content(): any {
        return {
            commitment: this.commitment
        };
    }

    public toWire(): Buffer {
        return this.commitment;
    }
}

/**
 * Round1 handles:
 * 1. Generating partial key share ui using secp256k1 order.
 * 2. Generating VSS shares using the polynomial approach.
 * 3. Creating and broadcasting the hash commitment from the VSS data.
 */
export class Round1 extends BaseRound implements Round {
    public number = 1;
    protected ok: boolean[];

    constructor(
        protected params: KeygenParams,
        protected data: LocalPartySaveData,
        protected temp: LocalTempData,
        protected out: (msg: MessageFromTss) => void,
        protected end: (data: LocalPartySaveData) => void,
    ) {
        super(params, data, temp, out, end);
        this.ok = new Array(params.totalParties).fill(false);
    }

    public async start(): Promise<TssError | null> {
        if (this.started) {
            return new TssError('round already started');
        }

        const partyID = this.params.partyID();
        const arrayIdx = partyID.arrayIndex;
        this.started = true;

        const temp = this.temp;

    
        temp.vs = Array(this.params.threshold + 1).fill(null);


     //   try {
            // 1. Generate partial key share (ui) using secp256k1 order
            const ui = getRandomPositiveInt(this.params.ec.n);
            if (!ui) return new TssError('failed to generate ui');
            this.temp.ui = ui;

            // 2. Generate VSS shares using polynomial creation
            const [vs, shares] = await Create(
                this.params.threshold,
                ui,
                this.params.parties.map(p => p.keyInt()),
                this.params.ec,
                this.params.rand
            );

            if (!vs || !shares) {
                return new TssError('failed to generate VSS shares');
            }

            // Store VSS data
            this.temp.vs = vs;
            this.temp.shares = shares;
            this.data.ks = this.params.parties.map(p => p.keyInt());

            // 3. Generate commitments using secp256k1 points
            const flatPoints = ECPoint.flattenECPoints(vs);
            const commitment = HashCommitment.new(...flatPoints);

            // Store commitment data
            this.temp.deCommitPolyG = commitment.D;
            this.data.shareID = this.params.parties[partyID.index - 1].keyInt();

            // Initialize message array and create a broadcast message
            this.temp.kgRound1Messages = new Array(this.params.totalParties);
            const msg = new KGRound1Message(
                partyID,
                commitment.C.toBuffer('be', 32)
            );

            this.temp.kgRound1Messages[arrayIdx] = msg;
            this.ok[arrayIdx] = true;
            this.out(msg);

            return null;
        // } catch (error) {
        //     return new TssError(error instanceof Error ? error.message : String(error));
        // }
    }

    public update(msg: ParsedMessage): [boolean, TssError | null] {
        try {
            const fromParty = msg.getFrom();
            const fromPIdx = fromParty.arrayIndex;

            // Validate party index
            if (fromPIdx < 0 || fromPIdx >= this.params.totalParties) {
                return [false, new TssError('invalid party array index')];
            }

            // Skip messages from self
            if (fromPIdx === this.params.partyID().arrayIndex) {
                return [true, null];
            }

            // Check for duplicates
            if (this.ok[fromPIdx]) {
                return [false, new TssError('duplicate message')];
            }

            // Store message and mark as received
            this.temp.kgRound1Messages[fromPIdx] = msg as KGRound1Message;
            this.ok[fromPIdx] = true;

            return [true, null];
        } catch (err) {
            return [false, new TssError(err instanceof Error ? err.message : String(err))];
        }
    }

    public canProceed(): boolean {
        const allHaveSent = this.ok.every(val => val);
        return allHaveSent && this.started;
    }
}