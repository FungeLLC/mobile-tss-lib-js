import BN from 'bn.js';
import crypto from 'crypto';

class Commitment {
    private value: BN;

    constructor(value: BN) {
        this.value = value;
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

class Shares {
    private shares: BN[];

    constructor() {
        this.shares = [];
    }

    public addShare(share: BN): void {
        this.shares.push(share);
    }

    public getShare(index: number): BN {
        return this.shares[index];
    }
}

interface KeygenParams {
	noProofFac: any;
	ec(contextI: Buffer, ec: any, n: any, arg3: any, arg4: any, arg5: any, p: any, q: any, rand: any): any;
	rand(contextI: Buffer, ec: any, n: any, arg3: any, arg4: any, arg5: any, p: any, q: any, rand: any): any;
	noProofMod: any;
    totalParties: number;
    partyID(): PartyID;
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

interface ParsedMessage {
    getFrom(): PartyID;
    content(): any;
}

interface PartyID {
    index: number;
}

interface Round {
    start(): TssError | null;
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

interface BaseParty {
    start(party: any, taskName: string): TssError | null;
    update(party: any, msg: ParsedMessage, taskName: string): [boolean, TssError | null];
    parseWireMessage(wireBytes: Uint8Array, from: PartyID, isBroadcast: boolean): ParsedMessage | TssError;
    validateMessage(msg: ParsedMessage): [boolean, TssError | null];
    toString(): string;
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

export { KeygenParams, LocalPartySaveData, LocalPreParams, ParsedMessage, PartyID, Round, TssError, MessageFromTss, BaseParty, LocalTempData, Commitment, Shares };