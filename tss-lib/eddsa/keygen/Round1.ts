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

class KGRound1Message implements ParsedMessage {

    public isBroadcast: boolean;

    constructor(
        private from: PartyID,
        private commitment: Buffer,
        public wireBytes: Uint8Array
    ) { 
        this.isBroadcast = true;
    }
    
    public marshal(): Uint8Array {
        const content = this.content();
        return Buffer.from(JSON.stringify(content));
    }

    public static unmarshal(bytes: Uint8Array): KGRound1Message {
        const content = JSON.parse(Buffer.from(bytes).toString());
        return new KGRound1Message(
            content.from,
            Buffer.from(content.commitment, 'hex'),
            bytes
        );
    }

    public getFrom(): PartyID {
        return this.from;
    }

    public content(): any {
        return {
            from: this.from,
            commitment: this.commitment.toString('hex')
        };
    }

    public unmarshalCommitment(): Buffer {
        return this.commitment;
    }
}

class Round1 extends BaseRound implements Round {
    constructor(
        protected params: KeygenParams,
        protected data: LocalPartySaveData,
        protected temp: LocalTempData,
        protected out: (msg: MessageFromTss) => void,
        protected end: (data: LocalPartySaveData) => void,
    ) {
        super(params, data, temp, out, end);
        this.number = 1;
    }

    public async start(): Promise<TssError | null> {
        if (this.started) {
            return Promise.resolve(new TssError('round already started'));
        }
        this.started = true;

        try {
            // Calculate partial key share ui
            const ui = getRandomPositiveInt(this.params.ec.n) as BN;
            this.temp.ui = ui;

            // Generate VSS shares
            const [vs, shares] = Create(
                this.params.threshold,
                ui,
                this.params.parties.map(p => p.keyInt()),
                this.params.ec.curve,
                this.params.rand
            );

            // Store VSS data
            this.temp.vs = vs;
            this.temp.shares = shares;

            // Generate commitments
            const flatPoints = ECPoint.flattenECPoints(vs);
            const commitment = HashCommitment.new(...flatPoints);

            // Store commitment data
            this.temp.deCommitPolyG = commitment.D;
            this.temp.KGCs[this.params.partyID().index] = {
                value: flatPoints[0],
                commitment: new Uint8Array(commitment.C.toArray('be', 32)),
                toBytes: () => new Uint8Array(commitment.C.toArray('be', 32)),
                verify: (share: BN): boolean => {
                    const hash = new BN(crypto.createHash('sha256').update(Buffer.from(share.toArray())).digest('hex'), 16);
                    return flatPoints[0].eq(hash);
                }
            };

            // Broadcast commitment
            const msg = new KGRound1Message(
                this.params.partyID(),
                commitment.C.toBuffer('be', 32),
                Buffer.from([])
            );

            this.temp.kgRound1Messages[this.params.partyID().index] = msg;
            this.out({
                wireBytes: Buffer.from(JSON.stringify(msg.content())),
                from: this.params.partyID(),
                isBroadcast: true,
                getFrom: () => this.params.partyID(),
                content: () => msg.content()
            });

            return Promise.resolve(null);
        } catch (error) {
            return Promise.resolve(new TssError(error instanceof Error ? error.message : String(error)));
        }
    }

    public update(msg: ParsedMessage): [boolean, TssError | null] {
        const fromPIdx = msg.getFrom().index;

        if (fromPIdx >= this.params.totalParties) {
            return [false, new TssError(`party index out of bounds: ${fromPIdx}`)];
        }

        if (!(msg instanceof KGRound1Message)) {
            return [false, new TssError('invalid message type')];
        }

        this.temp.kgRound1Messages[fromPIdx] = msg;
        this.ok[fromPIdx] = true;

        return [true, null];
    }
}

export { Round1, KGRound1Message };