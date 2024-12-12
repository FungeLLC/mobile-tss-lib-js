import BN from 'bn.js';
import { ParsedMessage, Commitment } from './interfaces';
import { ECPoint } from '../../crypto/ECPoint';
import { Shares } from '../../crypto/VSS';
import { KGRound1Message } from './Round1';
import { KGRound2Message1 } from './KGRound2Message1';
import { KGRound2Message2 } from './KGRound2Message2';
import { KGRound3Message } from './KGRound3Message';

export class LocalTempData {
    // Message storage
    public kgRound1Messages: Array<KGRound1Message | null>;
    public kgRound2Message1s: Array<KGRound2Message1 | null>;
    public kgRound2Message2s: Array<KGRound2Message2 | null>;
    public kgRound3Messages: Array<KGRound3Message | null>;

    // Commitment data
    public KGCs: Array<Commitment | null>;
    public deCommitPolyG: BN[];

    // VSS data
    public vs: ECPoint[];
    public shares: Shares;

    // Session identifiers
    public ssid: Uint8Array;
    public ssidNonce: BN;

    // Round state
    public started: boolean;

    // Temporary values used during key generation
    public ui: BN;

    constructor(partyCount: number) {
        // Initialize message arrays
        this.kgRound1Messages = new Array(partyCount).fill(null);
        this.kgRound2Message1s = new Array(partyCount).fill(null);
        this.kgRound2Message2s = new Array(partyCount).fill(null);
        this.kgRound3Messages = new Array(partyCount).fill(null);

        // Initialize commitment data
        this.KGCs = new Array(partyCount).fill(null);
        this.deCommitPolyG = [];

        // Initialize VSS data
        this.vs = [];
        this.shares = [];

        // Initialize session identifiers
        this.ssid = new Uint8Array(0);
        this.ssidNonce = new BN(0);

        // Initialize state
        this.started = false;

        // Initialize temporary values
        this.ui = new BN(0);
    }

    public clear(): void {
        this.kgRound1Messages.fill(null);
        this.kgRound2Message1s.fill(null);
        this.kgRound2Message2s.fill(null);
        this.kgRound3Messages.fill(null);
        this.KGCs.fill(null);
        this.deCommitPolyG = [];
        this.vs = [];
        this.shares = [];
        this.ssid = new Uint8Array(0);
        this.ssidNonce = new BN(0);
        this.started = false;
        this.ui = new BN(0);
    }
}