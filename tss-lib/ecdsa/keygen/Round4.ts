import { MessageFromTss, Round, ParsedMessage, PartyID } from './interfaces';
import { KeygenParams } from './KeygenParams';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import { BaseRound } from './Rounds';
import { ECPoint } from '../../crypto/ECPoint';
import { KGRound4Message } from './KGRound4Message';

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

  public async start(): Promise<TssError | null> {
    if (this.started) {
      return new TssError('round already started');
    }
    this.started = true;

    // Ensure local share and final pubkey were computed in Round3
    if (!this.data.xi) {
      return new TssError('private share (xi) is missing');
    }
    if (!this.data.ecdsaPub) {
      return new TssError('ECDSA public key not set');
    }

    // Final key verification
    if (!this.verifyFinalKey()) {
      return new TssError('final key verification failed');
    }

    // Send Round4 completion message to all parties
    const partyID = this.params.partyID();
    const msg = new KGRound4Message(partyID);

    // Mark our message as received
    const arrayIdx = partyID.arrayIndex;
    this.ok[arrayIdx] = true;

    // Broadcast to other parties
    this.out(msg);

    // Round4 done; call end
    this.end(this.data);
    return null;
  }

  public update(msg: ParsedMessage): [boolean, TssError | null] {
    try {
        const fromParty = msg.getFrom();
        const fromPIdx = fromParty.arrayIndex;

        // Validate party index
        if (fromPIdx < 0 || fromPIdx >= this.params.totalParties) {
            return [false, new TssError('invalid party array index')];
        }

        // Skip messages from self
        if (fromPIdx === this.params.partyID().arrayIndex) {
            return [true, null];
        }

        // Check for duplicates
        if (this.ok[fromPIdx]) {
            return [false, new TssError('duplicate message in round 4')];
        }

        // Mark message as received
        this.ok[fromPIdx] = true;

        // If round is complete, call end
        if (this.isComplete()) {
            this.end(this.data);
            return [true, null];
        }

        return [true, null];
    } catch (err) {
        return [false, new TssError(err instanceof Error ? err.message : String(err))];
    }
}

  private handleMessage(msg: ParsedMessage): TssError | null {
    const fromPIdx = msg.getFrom().arrayIndex;
    this.ok[fromPIdx] = true;
    return null;
  }

  public isComplete(): boolean {
    return this.started && this.ok.every(x => x);
  }

  /**
   * Verify final key correctness:
   *  1. Reconstruct G from curve
   *  2. Multiply G by xi
   *  3. Confirm it matches data.ecdsaPub
   */
  private verifyFinalKey(): boolean {
    const share = this.data.xi;
    if (!share) {
      return false;
    }
    try {
      // Reconstruct generator point
      const G = new ECPoint(
        this.params.ec,
        this.params.ec.g.getX(),
        this.params.ec.g.getY()
      );
      const computed = G.mul(share);

      // Compare to stored ecdsaPub
      return this.data.ecdsaPub?.equals(computed) ?? false;
    } catch {
      return false;
    }
  }
}