import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import { BaseRound } from './Rounds';
import { ECPoint } from '../../crypto/ECPoint';
import BN from 'bn.js';

export class Round4 extends BaseRound implements Round {
	public number = 4;
	public ok: boolean[];
	
	constructor(
		protected params: KeygenParams,
		protected data: LocalPartySaveData,
		protected temp: LocalTempData,
		protected out: (msg: MessageFromTss) => void,
		protected end: (data: LocalPartySaveData) => void,
	) {
		super(params, data, temp, out, end);
		this.ok = new Array(params.totalParties).fill(false);
	}

    update(msg: ParsedMessage): [boolean, TssError | null] {
        const fromPIdx = msg.getFrom().arrayIndex;
        if (fromPIdx < 0 || fromPIdx >= this.params.totalParties) {
            return [false, new TssError('unexpected message in round 4')];
        }

        const err = this.handleMessage(msg);
        if (err) {
            return [false, err];
        }
        
        if (this.isComplete()) {
            return [true, null];
        }
        
        return [false, null];
    }

    public async start(): Promise<TssError | null> {
        try {
            if (this.started) {
                return new TssError('round already started');
            }
            this.started = true;

            const partyID = this.params.partyID();
            const arrayIdx = partyID.arrayIndex;

            const ecdsaPub = this.data.eddsaPub;
            if (!ecdsaPub) {
                return new TssError('ed25519 public key not set');
            }

            // Final key verification
            if (!this.verifyFinalKey()) {
                return new TssError('final key verification failed');
            }

            this.end(this.data);
            return null;

        } catch (error) {
            return new TssError(error instanceof Error ? error.message : String(error));
        }
    }

    public handleMessage(msg: ParsedMessage): TssError | null {
        const fromPIdx = msg.getFrom().arrayIndex;
        if (fromPIdx < 0 || fromPIdx >= this.params.totalParties) {
            return new TssError('invalid party array index');
        }

        this.ok[fromPIdx] = true;
        return null;
    }

    public isComplete(): boolean {
        if (!this.started) return false;
        return this.ok.every(v => v);
    }

    private verifyFinalKey(): boolean {
        try {
            // Verify that our private share generates the expected public key
            const share = this.data.xi;
            if (!share) {
                return false;
            }

            // Generate public key point
            const pubKeyPoint = ECPoint.scalarBaseMult(
                this.params.ec.curve,
                share
            );

            // Point validation specific to Edwards curve
            if (!pubKeyPoint.isOnCurve()) {
                return false;
            }

            // Verify it matches the stored public key
            const isEqual = this.data.eddsaPub?.equals(pubKeyPoint) ?? false;
            if (!isEqual) {
                console.error('Public key verification failed:', {
                    expected: this.data.eddsaPub,
                    actual: pubKeyPoint
                });
            }
            return isEqual;

        } catch (error) {
            console.error('Final key verification failed:', error);
            return false;
        }
    }
}
