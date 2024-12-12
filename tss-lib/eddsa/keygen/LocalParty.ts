import { ParsedMessage, PartyID, Round, MessageFromTss, Commitment } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import BN from 'bn.js';
import { Round1 } from './Round1';
import { Round2 } from './Round2';
import { Round3 } from './Round3';
import { Round4 } from './Round4';
import { BaseParty } from '../../common/BaseParty';
import { TssError } from '../../common/TssError';
import { LocalPreParams } from './LocalPreParams';
import { Shares } from '../../crypto/VSS';
import { ECPoint } from '../../crypto/ECPoint';

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
        this.out = out;
        this.end = end;

        if (optionalPreParams) {
            if (!optionalPreParams.validateWithProof()) {
                throw new Error('`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib');
            }
            this.data.localPreParams = optionalPreParams;
        }

        this.baseParty = new BaseParty(params);
        this.params = params;
        this.temp = new LocalTempData(partyCount);
        this.currentRound = new Round1(params, this.data, this.temp, this.out, this.end);
    }

    public getPublicKey(): ECPoint | undefined {
        if (!this.data?.eddsaPub) {
            console.warn('Public key not yet generated');
            return undefined;
        }
        return this.data.eddsaPub;
    }

    // public start(): TssError | null {
    //     return this.baseParty.start(this, 'eddsa-keygen');
    // }
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
        if (this.currentRound.canProceed()) {
            if (this.currentRound instanceof Round1) {
                this.currentRound = new Round2(this.params, this.data, this.temp, this.out, this.end);
            } else if (this.currentRound instanceof Round2) {
                this.currentRound = new Round3(this.params, this.data, this.temp, this.out, this.end);
            } else if (this.currentRound instanceof Round3) {
                this.currentRound = new Round4(this.params, this.data, this.temp, this.out, this.end);
            }
            await this.currentRound.start();
        }
    }

    public firstRound(): Round {
        return new Round1(this.params, this.data, this.temp, this.out, this.end);
    }

    public partyID(): PartyID {
        return this.params.partyID();
    }

    public update(msg: MessageFromTss): [boolean, TssError | null] {
        const [ok, err] = this.baseParty.update(this, msg, 'eddsa-keygen');
        if (ok && this.currentRound instanceof Round4 && this.currentRound.canProceed()) {
            this.isComplete = true;
        }
        return [ok, err];
    }

    public isKeyGenComplete(): boolean {
        return this.isComplete;
    }

    // Update end method to set completion
    private async processCurrentRound(): Promise<void> {
        const result = await this.currentRound.start();
        if (result) {
            throw result;
        }
        if (this.currentRound instanceof Round1) {
            this.currentRound = new Round2(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round2) {
            this.currentRound = new Round3(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round3) {
            this.currentRound = new Round4(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round4) {
            this.isComplete = true;
        }
    }
}
export { LocalParty };