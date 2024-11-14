import { KeygenParams, MessageFromTss, Round } from './interfaces';
import BN from 'bn.js';
import { Commitment, Shares } from './interfaces';
import { generateCommitment, generateShares } from './utils';
import { ParsedMessage } from './interfaces';
import { TssError } from './TssError';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';

class Round1 implements Round {
    constructor(
        private params: KeygenParams,
        private data: LocalPartySaveData,
        private temp: LocalTempData,
        private out: (msg: MessageFromTss) => void,
        private end: (data: LocalPartySaveData) => void
    ) {}

    public start(): TssError | null {
        try {
            // Generate commitments and shares
            this.temp.KGCs = generateCommitment(this.params.totalParties);
            this.temp.shares = generateShares(this.params.totalParties);

            // Broadcast the commitments
            this.broadcastCommitments();

            return null;
        } catch (error) {
            return new TssError(error);
        }
    }

    private broadcastCommitments(): void {
        for (let i = 0; i < this.params.totalParties; i++) {
            const msg: MessageFromTss = {
                wireBytes: this.temp.KGCs[i].toBytes(),
                from: this.params.partyID().index.toString(),
                isBroadcast: true
            };
            this.out(msg);
        }
    }

    public update(msg: ParsedMessage): [boolean, TssError | null] {
        const fromPIdx = msg.getFrom().index;

        switch (msg.content().constructor.name) {
            case 'KGRound1Message':
                this.temp.kgRound1Messages[fromPIdx] = msg;
                break;
            default:
                return [false, new TssError(`unrecognised message type: ${msg.content().constructor.name}`)];
        }

        // Check if all messages are received
        if (this.temp.kgRound1Messages.every((m: ParsedMessage | undefined) => m !== undefined)) {
            this.endRound();
        }

        return [true, null];
    }

    private endRound(): void {
        try {
            // Process the received commitments and shares
            this.processCommitmentsAndShares();

            // Move to the next round
            this.end(this.data);
        } catch (error) {
            throw new TssError(error);
        }
    }

    private processCommitmentsAndShares(): void {
        // Implement the logic to process the received commitments and shares
        for (let i = 0; i < this.params.totalParties; i++) {
            const commitment = this.temp.KGCs[i];
            const share: BN = this.temp.shares.getShare(i);

            // Verify the commitment and share
            if (!this.verifyCommitmentAndShare(commitment, share)) {
                throw new Error(`Invalid commitment or share from party ${i}`);
            }

            this.data.combinedShares.addShare(share);
        }
    }

    private verifyCommitmentAndShare(commitment: Commitment, share: BN): boolean {
        // 1. Verify that the commitment matches the share
        // 2. Verify that the share is within the expected range

        return commitment.verify(share);
    }
}

export { Round1 };