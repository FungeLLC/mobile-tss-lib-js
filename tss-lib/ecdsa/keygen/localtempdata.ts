import BN from 'bn.js';
import { ParsedMessage, Commitment } from './interfaces';
import { ECPoint } from '../../crypto/ECPoint';
import { Shares } from '../../crypto/VSS';
import { KGRound1Message } from './Round1';
import { KGRound2Message1 } from './KGRound2Message1';
import { KGRound2Message2 } from './KGRound2Message2';

class LocalTempData {
    kgRound1Messages: Array<KGRound1Message | null>;
    kgRound2Message1s: Array<KGRound2Message1| null>;
    kgRound2Message2s: Array<KGRound2Message2 | null>;
    kgRound3Messages: Array<ParsedMessage | null>;
    KGCs: Array<Commitment | null>;
    vs: ECPoint[];
    ssid: Uint8Array;
    ssidNonce: BN;
    shares: Shares;
    deCommitPolyG: BN[];
    started: boolean;
    ui!: BN;
    xi!: BN;



    constructor(partyCount: number) {
        this.kgRound1Messages = new Array(partyCount).fill(null);
        this.kgRound2Message1s = new Array(partyCount).fill(null);
        this.kgRound2Message2s = new Array(partyCount).fill(null);
        this.kgRound3Messages = new Array(partyCount).fill(null);
        this.KGCs = new Array(partyCount).fill(null);
        this.vs = new Array<ECPoint>();
        this.ssid = new Uint8Array();
        this.ssidNonce = new BN(0);
        this.shares = {} as Shares;
        this.deCommitPolyG = [];
        this.started = false;
    }
}

export { LocalTempData };