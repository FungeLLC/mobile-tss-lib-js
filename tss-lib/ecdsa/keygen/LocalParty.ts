import { ParsedMessage, PartyID, Round, MessageFromTss, Commitment } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import BN from 'bn.js';
import { Round1 } from './Round1';
import { Round2 } from './Round2';
import { Round3 } from './Round3';
import { Round4 } from './Round4';
import { Round5 } from './Round5';

import { BaseParty } from '../../common/BaseParty';
import { TssError } from '../../common/TssError';
import { LocalPreParams } from './LocalPreParams';
import { ECPoint } from '../../crypto/ECPoint';
import { Shares } from '../../crypto/VSS';


class LocalParty {
    private baseParty: BaseParty;
    private params: KeygenParams;
    private temp: LocalTempData;
    private data: LocalPartySaveData;
    private out: (msg: MessageFromTss) => void;
    private end: (data: LocalPartySaveData) => void;
    private currentRound: Round;
    private isComplete: boolean = false;

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
            vs: [],
            ssid: new Uint8Array(),
            ssidNonce: new BN(0),
            shares: [],
            deCommitPolyG: [],
            started: false,
            ui: new BN(0),
        };
        this.out = out;
        this.end = end;
        this.currentRound = new Round1(params, this.data, this.temp, this.out, this.end);
    }

    public getPublicKey(): ECPoint | undefined {
        // Make sure ecdsaPub is set after key generation
        if (!this.data?.ecdsaPub) {
            console.warn('Public key not yet generated');
            return undefined;
        }
        return this.data.ecdsaPub;
    }


    public firstRound(): Round {
        return new Round1(this.params, this.data, this.temp, this.out, this.end);
    }

    public async start(): Promise<TssError | null> {
        try {
            const result = await this.currentRound.start();
            if (result) {
                return result;
            }
            // Ensure public key is generated
            await this.processRound();
            return null;
        } catch (error) {
            return new TssError(error instanceof Error ? error.message : String(error));
        }
    }


    private async processRound(): Promise<void> {
        console.log(`Processing ${this.currentRound.constructor.name}, canProceed: ${this.currentRound.canProceed()}`);
        
        if (!this.currentRound.canProceed()) {
            return;
        }
    
        let nextRound: Round;
        if (this.currentRound instanceof Round1) {
            nextRound = new Round2(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round2) {
            nextRound = new Round3(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round3) {
            nextRound = new Round4(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round4) {
            nextRound = new Round5(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round5) {
            this.isComplete = true;
            if (!this.data.ecdsaPub) {
                this.data.ecdsaPub = this.getPublicKey();
            }
            return;
        } else {
            throw new Error(`Unknown round type: ${this.currentRound.constructor.name}`);
        }
    
        this.currentRound = nextRound;
        const err = await this.currentRound.start();
        if (err) {
            throw err;
        }
    }
    // public start(): TssError | null {
    //     return this.baseParty.start(this, 'ecdsa-keygen');
    // }

    public update(msg: ParsedMessage): [boolean, TssError | null] {
        return this.baseParty.update(this, msg, 'ecdsa-keygen');
    }

    public updateFromBytes(wireBytes: Uint8Array, from: PartyID, isBroadcast: boolean): [boolean, TssError | null] {
        const msg = this.baseParty.parseWireMessage(wireBytes, from, isBroadcast);
        if (msg instanceof TssError) {
            return [false, msg];
        }
        return this.update(msg);
    }

    public validateMessage(msg: ParsedMessage): [boolean, TssError | null] {
        const ok = this.baseParty.validateMessage(msg);
        if (!ok ) {
            return [ok, new TssError('message validation failed')];
        }
        if (this.params.totalParties - 1 < msg.getFrom().index) {
            return [false, new TssError([`received msg with a sender index too great (${this.params.totalParties} <= ${msg.getFrom().index})`, msg.getFrom()])];
        }
        return [true, null];
    }

    public storeMessage(msg: any): [boolean, TssError | null] {
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