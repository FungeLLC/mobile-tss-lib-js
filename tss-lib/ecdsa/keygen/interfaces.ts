import BN from 'bn.js';
import crypto from 'crypto';
import { ec as EC } from 'elliptic';
import { PartyID } from '../../common/PartyID';
import { Shares, Share } from '../../crypto/VSS';
import { CurveParams, ParsedMessage } from '../../common/Types';


class Commitment {
    public value: BN;
    commitment: Uint8Array;

    constructor(value: BN) {
        this.value = value;
        this.commitment = new Uint8Array(crypto.createHash('sha256').update(Buffer.from(this.value.toArray())).digest());
    }

    public toBytes(): Uint8Array {
        return new Uint8Array(this.value.toArray('be', 32)); // Convert to big-endian array with a length of 32 bytes
    }

    public verify(share: BN): boolean {
		// Assuming the commitment is a hash of the share, we can verify it by comparing the hash
        const hash = new BN(crypto.createHash('sha256').update(Buffer.from(share.toArray())).digest('hex'), 16);
		return this.value.eq(hash);
    }
}



interface LocalPartySaveData {
	localPreParams?: LocalPreParams;
	combinedShares: Shares;
	paillierPKs: any;
	NTildej: any;
	H1j: any;
	H2j: any;
	shareID: BN;
    ks: BN[];
    originalIndex(): number;
}

interface LocalPreParams {
    validateWithProof(): boolean;
}


// interface PartyID {
//     index: number;
//     keyInt(): BN;
//     toString(): string;
// }

interface Round {
    start(): Promise<TssError | null>;
    canProceed(): boolean;
    update(msg: ParsedMessage): [boolean, TssError | null];
}

interface TssError {

	name: string;

	message: string;

	stack?: string;

}


interface MessageFromTss {
    wireBytes: Uint8Array;
    from: PartyID;
    to?: PartyID;
    isBroadcast: boolean;
}


interface LocalTempData {
	kgRound1Messages: Array<ParsedMessage | null>;
	kgRound2Message1s: Array<ParsedMessage | null>;
	kgRound2Message2s: Array<ParsedMessage | null>;
	kgRound3Messages: Array<ParsedMessage | null>;
	KGCs: Array<Commitment | null>;
	vs: Shares;
	ssid: Uint8Array;
	ssidNonce: BN;
	shares: Shares;
	deCommitPolyG: Commitment;
	started: boolean;
}

export interface Message {
    wireBytes: Buffer;
    from: PartyID;
    to?: PartyID[];
    isBroadcast: boolean;
    content(): any;
    getFrom(): PartyID;
}

export interface Parameters {
    threshold: number;
    parties: PartyID[];
    partyID(): PartyID;
    partyCount(): number;
    ec: EC;
    ecParams: CurveParams;
}

export { LocalPartySaveData, LocalPreParams, ParsedMessage, PartyID, Round, TssError, MessageFromTss, LocalTempData, Commitment, Shares, Share };