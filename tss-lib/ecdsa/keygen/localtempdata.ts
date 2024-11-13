import { ParsedMessage, Commitment, Shares } from './interfaces';
import BN from 'bn.js';

class LocalTempData {
    public kgRound1Messages: ParsedMessage[];
    public kgRound2Message1s: ParsedMessage[];
    public kgRound2Message2s: ParsedMessage[];
    public kgRound3Messages: ParsedMessage[];
    public KGCs: Commitment[];
    public vs: Shares;
    public ssid: Uint8Array = new Uint8Array();
    public ssidNonce!: BN;
    public shares: Shares;
    public deCommitPolyG: Commitment;

    constructor(partyCount: number) {
        this.kgRound1Messages = new Array(partyCount);
        this.kgRound2Message1s = new Array(partyCount);
        this.kgRound2Message2s = new Array(partyCount);
        this.kgRound3Messages = new Array(partyCount);
        this.KGCs = new Array(partyCount);
    }
}

export { LocalTempData };