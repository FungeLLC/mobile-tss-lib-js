import BN from 'bn.js';

class Commitment {
    private value: BN;

    constructor(value: BN) {
        this.value = value;
    }

    public toBytes(): Uint8Array {
        return new Uint8Array(this.value.toArray('be', 32)); // Convert to big-endian array with a length of 32 bytes
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
}

interface KeygenParams {
    totalParties: number;
    partyID(): PartyID;
}

interface LocalPartySaveData {
    localPreParams?: LocalPreParams;
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
    from: string;
    to?: string;
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
    kgRound1Messages: ParsedMessage[];
    kgRound2Message1s: ParsedMessage[];
    kgRound2Message2s: ParsedMessage[];
    kgRound3Messages: ParsedMessage[];
    KGCs: Commitment[];
    vs: Shares;
    ssid: Uint8Array;
    ssidNonce: BN;
    shares: Shares;
    deCommitPolyG: Commitment;
}

export { KeygenParams, LocalPartySaveData, LocalPreParams, ParsedMessage, PartyID, Round, TssError, MessageFromTss, BaseParty, LocalTempData, Commitment, Shares };