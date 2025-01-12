import { ParsedMessage, PartyID, Round, MessageFromTss, Commitment, Message } from './interfaces';
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

export class LocalParty {
    private baseParty: BaseParty;
    private params: KeygenParams;
    private temp: LocalTempData;
    private data: LocalPartySaveData;
    private out: (msg: MessageFromTss) => void;
    private end: (data: LocalPartySaveData) => void;
    private currentRound: Round;
    private isComplete: boolean = false;
    private maxWaitTime = 30000; // 30 seconds timeout
    private messageQueue: Message[] = [];
    private processedMessages = new Set<string>();

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

    public getCurrentRound() {

        return this.currentRound;

    }

    public getPublicKey(): ECPoint | undefined {
        if (!this.data?.eddsaPub) {
            console.warn('Public key not yet generated');
            return undefined;
        }
        return this.data.eddsaPub;
    }

    public async start(): Promise<TssError | null> {
        try {
            console.log(`Starting key generation in round ${this.currentRound.constructor.name}`);
            const result = await this.currentRound.start();
            if (result) {
                return result;
            }

            const startTime = Date.now();
            while (!this.isComplete) {
                // Check timeout
                if (Date.now() - startTime > this.maxWaitTime) {
                    return new TssError('Key generation timed out');
                }

                // Process any queued messages
                while (this.messageQueue.length > 0) {
                    const msg = this.messageQueue.shift()!;
                    const [ok, err] = await this.currentRound.update(msg);
                    if (err) return err;
                }

                // Try to advance round
                await this.processRound();
                
                // Small delay to prevent CPU spin
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            return null;
        } catch (error) {
            return new TssError(error instanceof Error ? error.message : String(error));
        }
    }

    private async processRound(): Promise<void> {
        console.log(`[${this.currentRound.constructor.name}] Processing round`);
        
        let processedAnyMessage = false;
        // Process all messages in the queue first
        for (const msg of [...this.messageQueue]) {
            const msgId = `${msg.from}->${msg.to}`;
            if (!this.processedMessages.has(msgId)) {
                const [ok, err] = await this.currentRound.update(msg);
                if (err) throw err;
                if (ok) {
                    this.processedMessages.add(msgId);
                    processedAnyMessage = true;
                }
            }
        }

        // Clear processed messages from queue
        this.messageQueue = this.messageQueue.filter(msg => {
            const msgId = `${msg.from}->${msg.to}`;
            return !this.processedMessages.has(msgId);
        });

        console.log(`[${this.currentRound.constructor.name}] Can proceed: ${this.currentRound.canProceed()}`);
        if (!this.currentRound.canProceed() && !processedAnyMessage) {
            return;
        }

        let nextRound: Round | null = null;
        console.log(`[${this.currentRound.constructor.name}] Transitioning to next round`);

        if (this.currentRound instanceof Round1) {
            nextRound = new Round2(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round2) {
            nextRound = new Round3(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round3) {
            nextRound = new Round4(this.params, this.data, this.temp, this.out, this.end);
        } else if (this.currentRound instanceof Round4) {
            this.isComplete = true;
            if (!this.data.eddsaPub) {
                this.data.eddsaPub = this.generatePublicKey();
            }
            return;
        } else {
            throw new Error('Unknown round type');
        }

        this.currentRound = nextRound;
        await this.currentRound.start();
    }

    private generatePublicKey(): ECPoint {
        const share = this.data.xi;
        if (!share) {
            throw new Error('Private share (xi) is not set');
        }
    
        // Generate public key point
        const pubKeyPoint = ECPoint.scalarBaseMult(
            this.params.ec,
            share
        );
    
        // Point validation specific to Edwards curve
        if (!pubKeyPoint.isOnCurve()) {
            throw new Error('Generated public key point is not on the curve');
        }
    
        return pubKeyPoint;
    }

    public firstRound(): Round {
        return new Round1(this.params, this.data, this.temp, this.out, this.end);
    }

    public partyID(): PartyID {
        return this.params.partyID();
    }

    public async update(msg: Message): Promise<[boolean, TssError | null]> {
        const msgId = `${msg.from}->${msg.to}`;
        if (this.processedMessages.has(msgId)) {
            return [true, null];
        }
        
        const [ok, err] = await this.baseParty.update(this, msg, 'eddsa-keygen');
        if (ok) {
            this.processedMessages.add(msgId);
        }
        return [ok, err];
    }

    public isKeyGenComplete(): boolean {
        return this.isComplete;
    }

    public handleMessage(msg: Message): void {
        this.messageQueue.push(msg);
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