import { Message, Round, ParsedMessage, PartyID, MessageFromTss } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import { BaseRound } from './Rounds';
import { HashCommitment } from '../../crypto/Commitment';
import { Create } from '../../crypto/VSS';
import { ECPoint } from '../../crypto/ECPoint';
import { getRandomPositiveInt, getRandomSource } from '../../common/Random';
import BN from 'bn.js';
import { DLNProof } from '../../crypto/DLNProof';


class KGRound1Message implements ParsedMessage {
    constructor(
        private from: PartyID,
        private commitment: Buffer,
        private paillierPK: any,
        private nTilde: BN,
        private h1: BN,
        private h2: BN,
        private dlnProof1: DLNProof,
        private dlnProof2: DLNProof,
        public wireBytes: Uint8Array 
    ) {}

    public marshal(): Uint8Array {
        const content = this.content();
        return Buffer.from(JSON.stringify(content));
    }

    public static unmarshal(bytes: Uint8Array): KGRound1Message {
        const content = JSON.parse(Buffer.from(bytes).toString());
        return new KGRound1Message(
            content.from,
            Buffer.from(content.commitment, 'hex'),
            content.paillierPK,
            new BN(content.nTilde, 16),
            new BN(content.h1, 16),
            new BN(content.h2, 16),
            content.dlnProof1.unserialize(),
            content.dlnProof2.unserialize(),
            bytes
        );
    }
    isBroadcast: boolean = true;

    public getFrom(): PartyID {
        return this.from;
    }

    public content(): any {
        return {
            commitment: this.commitment,
            paillierPK: this.paillierPK,
            nTilde: this.nTilde.toString(16),
            h1: this.h1.toString(16),
            h2: this.h2.toString(16),
            dlnProof1: this.dlnProof1.serialize(),
            dlnProof2: this.dlnProof2.serialize(),
            wireBytes: this.wireBytes
        };
    }

    public unmarshalCommitment(): Buffer {
        return this.commitment;
    }

    public unmarshalPaillierPK(): any {
        return this.paillierPK;
    }

    public unmarshalNTilde(): BN {
        return this.nTilde;
    }

    public unmarshalH1(): BN {
        return this.h1;
    }

    public unmarshalH2(): BN {
        return this.h2;
    }

    public verifyDLNProof1(h1: BN, h2: BN, NTildej: BN): boolean {
        return this.dlnProof1.verify(h1, h2, NTildej);
    }

    public verifyDLNProof2(h2: BN, h1: BN, NTildej: BN): boolean {
        return this.dlnProof2.verify(h2, h1, NTildej);
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

    private generateDLNProof1(): DLNProof {
        const i = this.params.partyID().index;
        return DLNProof.newDLNProof(
            this.data.H1j[i],
            this.data.H2j[i],
            this.data.Alpha,
            this.data.P,
            this.data.Q,
            this.data.NTildej[i]
                );
    }

    private generateDLNProof2(): DLNProof {
        const i = this.params.partyID().index;
        return DLNProof.newDLNProof(
            this.data.H2j[i],
            this.data.H1j[i],
            this.data.Beta,
            this.data.P,
            this.data.Q,
            this.data.NTildej[i],
        );
    }

    public async start(): Promise<TssError | null> {
        try {
            if (this.started) {
                return new TssError('round already started');
            }
            this.started = true;
            this.resetOK();

            const Pi = this.params.partyID();
            const i = Pi.index;

            // 1. Calculate partial key share ui
            const uiRaw = getRandomPositiveInt(BigInt(this.params.ec.n.toString())) ?? BigInt(0);
            const ui = new BN(uiRaw.toString());
            this.temp.ui = ui;

            // 2. Generate VSS shares
            const [vs, shares] = Create(
                this.params.threshold,
                ui,
                this.params.parties.map(p => p.keyInt()),
                this.params.ec.curve,
                getRandomSource()
            );
            this.data.ks = shares.map((s: { id: BN }) => s.id);

            // Store VSS data
            this.temp.vs = vs;
            this.temp.shares = shares;

            // Generate commitments
            const flatPoints = ECPoint.flattenECPoints(vs);
            const commitment = HashCommitment.new(...flatPoints);

            // Store commitment data
            this.temp.deCommitPolyG = commitment.D;

            // Broadcast commitment, Paillier PK and proofs
            const msg = new KGRound1Message(
                this.params.partyID(),
                commitment.C.toBuffer(),
                this.data.paillierSK.publicKey,
                this.data.NTildej[this.params.partyID().index],
                this.data.H1j[this.params.partyID().index],
                this.data.H2j[this.params.partyID().index],
                this.generateDLNProof1(),
                this.generateDLNProof2(),
                Buffer.alloc(0)
            );

            this.temp.kgRound1Messages[this.params.partyID().index] = msg;
            this.out({
                wireBytes: Buffer.from(JSON.stringify(msg.content())),
                from: this.params.partyID(),
                isBroadcast: true
            });

            return null;
        } catch (error) {
            return this.wrapError(error instanceof Error ? error : new Error(String(error)));
        }
    }

    public update(msg: KGRound1Message): [boolean, TssError | null] {
        // Save the incoming Round1 message
        this.temp.kgRound1Messages[msg.getFrom().index] = msg;
        // Mark that we have a Round1 message from that party
        this.ok[msg.getFrom().index] = true;

        // If we have Round1 messages from everyone (or from threshold parties),
        // canProceed() will be true
        return [true, null];
    }

    public canProceed(): boolean {
        // For 3 parties, you might want all 3 to be OK in round1
        // or if threshold is less, adjust accordingly
        const allHaveSent = this.ok.every(val => val);
        return allHaveSent && this.started;
    }


    private unmarshalDLNProof1(): DLNProof | null {
        try {
            const msg = this.temp.kgRound1Messages[this.params.partyID().index];
            if(!msg) {
                return null;
            }
            return this.generateDLNProof1();
        } catch (err) {
            return null;
        }
    }

    private unmarshalDLNProof2(): DLNProof | null {
        try {
            const msg = this.temp.kgRound1Messages[this.params.partyID().index];
            if(!msg
                ) {
                return null;
            }
            return this.generateDLNProof2();
        } catch (err) {
            return null;
        }
    }

}

export { Round1, KGRound1Message };