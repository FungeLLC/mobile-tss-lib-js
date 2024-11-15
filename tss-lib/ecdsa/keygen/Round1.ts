import { Message, Round, ParsedMessage, PartyID, MessageFromTss } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from './TssError';
import { BaseRound } from './Rounds';
import { HashCommitment } from '../../crypto/Commitment';
import { VSS } from '../../crypto/VSS';
import { ECPoint } from '../../crypto/ECPoint';
import { getRandomPositiveInt } from '../../common/Random';
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
        private dlnProof1: any,
        private dlnProof2: any
    ) { }

    public getFrom(): PartyID {
        return this.from;
    }

    public content(): any {
        return {
            commitment: this.commitment,
            paillierPK: this.paillierPK,
            nTilde: this.nTilde,
            h1: this.h1,
            h2: this.h2,
            dlnProof1: this.dlnProof1,
            dlnProof2: this.dlnProof2
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

    public unmarshalDLNProof1(): any {
        return DLNProof.unmarshalDLNProof(this.dlnProof1);
    }

    public unmarshalDLNProof2(): any {
        return DLNProof.unmarshalDLNProof(this.dlnProof2);
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
            const [vs, shares] = VSS.create(
                this.params.ec.curve,
                this.params.partyThreshold,
                ui,
                this.params.parties.map(p => p.keyInt())
            );
            this.data.ks = shares.map(s => s.id);

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
                this.generateDLNProof2()
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

    private generateDLNProof1(): DLNProof {
        const i = this.params.partyID().index;

        return DLNProof.newDLNProof(
            this.data.H1j[i],    // h1
            this.data.H2j[i],    // h2
            this.data.Alpha,     // x (secret)
            this.data.P,         // p (prime)
            this.data.Q,         // q (prime)
            this.data.NTildej[i], // N
            //this.params.rand     // randomness source generated in the proof
        );


    }

    private generateDLNProof2(): DLNProof {
        const i = this.params.partyID().index;

       return DLNProof.newDLNProof(
            this.data.H2j[i],    // h1 (note: h2 and h1 are swapped)
            this.data.H1j[i],    // h2 (note: h1 and h2 are swapped) 
            this.data.Beta,      // x (secret)
            this.data.P,         // p (prime)
            this.data.Q,         // q (prime)
            this.data.NTildej[i], // N
            //this.params.rand     // randomness source
        );

     
    }

    public verifyDLNProof1(h1: BN, h2: BN, NTildej: BN): boolean {
        // Verify first DLN proof which shows h2 = h1^alpha
        const dlnProof1 = this.unmarshalDLNProof1();
        if (!dlnProof1) {
            return false;
        }
        return dlnProof1.verify(h1, h2, NTildej);
    }

    public verifyDLNProof2(h2: BN, h1: BN, NTildej: BN): boolean {
        // Verify second DLN proof which shows h1 = h2^beta
        const dlnProof2 = this.unmarshalDLNProof2();
        if (!dlnProof2) {
            return false;
        }
        return dlnProof2.verify(h2, h1, NTildej);
    }

    private unmarshalDLNProof1(): DLNProof | null {
        try {
            const msg = this.temp.kgRound1Messages[this.params.partyID().index];
            if(!msg) {
                return null;
            }
            return msg.unmarshalDLNProof1();
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
            return msg.unmarshalDLNProof2();
        } catch (err) {
            return null;
        }
    }

}

export { Round1, KGRound1Message };