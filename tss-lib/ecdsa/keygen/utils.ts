import { Commitment, Shares, ParsedMessage, PartyID, Share } from './interfaces';
import BN from 'bn.js';
import { TssError } from '../../common/TssError';


export function generateCommitment(partyCount: number): Commitment[] {
    const commitments: Commitment[] = [];
    for (let i = 0; i < partyCount; i++) {
        // Generate a random commitment
        const commitment = new Commitment(new BN(Math.floor(Math.random() * 1000)));
        commitments.push(commitment);
    }
    return commitments;
}

export function generateShares(partyCount: number, threshold: number): Shares {
    const shares: Shares = [];
    for (let i = 0; i < partyCount; i++) {
        // Generate a random share
        const shareValue = new BN(Math.floor(Math.random() * 1000));
        const share = new Share(threshold, new BN(i), shareValue);
        shares.push(share);
    }
    return shares;
}

export function parseWireMessage(wireBytes: Uint8Array, from: PartyID, isBroadcast: boolean): ParsedMessage | TssError {
    try {
        // Implement the logic to parse wire message
        const message = JSON.parse(Buffer.from(wireBytes).toString('utf-8'));
        return {
            getFrom: () => from,
            content: () => message,
        } as ParsedMessage;
    } catch (error) {
        return new TssError(error);
    }
}

export function BaseStart(party: any, taskName: string): TssError | null {
    try {
        // Implement the logic to start the base party
        party.firstRound().start();
        return null;
    } catch (error) {
        return new TssError(error);
    }
}

export function BaseUpdate(party: any, msg: ParsedMessage, taskName: string): [boolean, TssError | null] {
    try {
        // Implement the logic to update the base party
        const [ok, err] = party.update(msg);
        if (!ok || err) {
            return [false, err];
        }
        return [true, null];
    } catch (error) {
        return [false, new TssError(error)];
    }
}

export function WrapError(error: Error): TssError {
    return new TssError(error.message);
}
