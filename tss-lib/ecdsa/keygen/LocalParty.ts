import { KeygenParams, LocalPreParams, ParsedMessage, PartyID, Round, MessageFromTss, LocalTempData, Shares, Commitment } from './interfaces';
import { LocalPartySaveData } from './LocalPartySaveData';
import BN from 'bn.js';
import { Round1 } from './Round1';
import { Round2 } from './Round2';
import { Round3 } from './Round3';
import { BaseParty } from './BaseParty';
import { TssError } from './TssError';

class LocalParty {
    private baseParty: BaseParty;
    private params: KeygenParams;
    private temp: LocalTempData;
    private data: LocalPartySaveData;
    private out: (msg: MessageFromTss) => void;
    private end: (data: LocalPartySaveData) => void;

    constructor(params: KeygenParams, out: (msg: MessageFromTss) => void, end: (data: LocalPartySaveData) => void, optionalPreParams?: LocalPreParams) {
        const partyCount = params.totalParties;
        this.data = new LocalPartySaveData(partyCount);

        if (optionalPreParams) {
            if (!optionalPreParams.validateWithProof()) {
                throw new Error('`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib');
            }
            this.data.localPreParams = optionalPreParams;
        }

        this.baseParty = new BaseParty(params);
        this.params = params;
        this.temp = {
            kgRound1Messages: new Array(partyCount),
            kgRound2Message1s: new Array(partyCount),
            kgRound2Message2s: new Array(partyCount),
            kgRound3Messages: new Array(partyCount),
            KGCs: new Array(partyCount),
            vs: new Shares(),
            ssid: new Uint8Array(),
            ssidNonce: new BN(0),
            shares: new Shares(),
            deCommitPolyG: new Commitment(new BN(0))
        };
        this.out = out;
        this.end = end;
    }

    public firstRound(): Round {
        return new Round1(this.params, this.data, this.temp, this.out, this.end);
    }

    public start(): TssError | null {
        return this.baseParty.start(this, 'keygen');
    }

    public update(msg: ParsedMessage): [boolean, TssError | null] {
        return this.baseParty.update(this, msg, 'keygen');
    }

    public updateFromBytes(wireBytes: Uint8Array, from: PartyID, isBroadcast: boolean): [boolean, TssError | null] {
        const msg = this.baseParty.parseWireMessage(wireBytes, from, isBroadcast);
        if (msg instanceof TssError) {
            return [false, msg];
        }
        return this.update(msg as ParsedMessage);
    }

    public validateMessage(msg: ParsedMessage): [boolean, TssError | null] {
        const [ok, err] = this.baseParty.validateMessage(msg);
        if (!ok || err) {
            return [ok, err];
        }
        if (this.params.totalParties - 1 < msg.getFrom().index) {
            return [false, new TssError(`received msg with a sender index too great (${this.params.totalParties} <= ${msg.getFrom().index})`)];
        }
        return [true, null];
    }

    public storeMessage(msg: ParsedMessage): [boolean, TssError | null] {
        const [ok, err] = this.validateMessage(msg);
        if (!ok || err) {
            return [ok, err];
        }
        const fromPIdx = msg.getFrom().index;

        switch (msg.content().constructor) {
            case 'KGRound1Message':
                this.temp.kgRound1Messages[fromPIdx] = msg;
                break;
            case 'KGRound2Message1':
                this.temp.kgRound2Message1s[fromPIdx] = msg;
                break;
            case 'KGRound2Message2':
                this.temp.kgRound2Message2s[fromPIdx] = msg;
                break;
            case 'KGRound3Message':
                this.temp.kgRound3Messages[fromPIdx] = msg;
                break;
            default:
                console.warn(`unrecognised message ignored: ${msg}`);
                return [false, null];
        }
        return [true, null];
    }

    public partyID(): PartyID {
        return this.params.partyID();
    }

    public toString(): string {
        return `id: ${this.partyID()}, ${this.baseParty.toString()}`;
    }
}

export { LocalParty };