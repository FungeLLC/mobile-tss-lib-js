import BN from 'bn.js';
import { ParsedMessage, Commitment, Shares } from './interfaces';

class LocalTempData {
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

    constructor(partyCount: number) {
        this.kgRound1Messages = new Array(partyCount).fill(null);
        this.kgRound2Message1s = new Array(partyCount).fill(null);
        this.kgRound2Message2s = new Array(partyCount).fill(null);
        this.kgRound3Messages = new Array(partyCount).fill(null);
        this.KGCs = new Array(partyCount).fill(null);
        this.vs = new Shares();
        this.ssid = new Uint8Array();
        this.ssidNonce = new BN(0);
        this.shares = new Shares();
        this.deCommitPolyG = new Commitment(new BN(0));
        this.started = false;
    }
}

export { LocalTempData };