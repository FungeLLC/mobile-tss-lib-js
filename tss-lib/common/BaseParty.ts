import { ParsedMessage } from './Types';
import { TssError } from './TssError';
import { PartyID } from './PartyID';

interface Params {
	totalParties: number;
	partyID(): PartyID;
	parties: PartyID[];
	threshold: number;
}

class BaseParty {
	private started: boolean = false;
	private ok: boolean[];

	constructor(public params: Params) {
		this.ok = new Array(params.totalParties).fill(false);
	}

	public start(party: any, taskName: string): TssError | null {
		if (this.started) {
			return new TssError('round already started');
		}
		try {
			this.started = true;
			this.resetOK();
			party.firstRound().start();
			return null;
		} catch (error) {
			return new TssError(error instanceof Error ? error.message : String(error));
		}
	}

	public update(party: any, msg: ParsedMessage, taskName: string): [boolean, TssError | null] {
		try {
			console.log(`[${taskName}] ${msg.getFrom().index} -> ${this.params.partyID().index}`);
			if (msg.getFrom().index === this.params.partyID().index) {
				// ignore message from self to avoid infinite loop
				return [true, null];
			}
			if (!this.validateMessage(msg)) {
				return [false, new TssError('message validation failed')];
			}
			if (msg.getFrom().index >= this.params.totalParties) {
				return [false, new TssError('party index out of bounds')];
			}
			console.log(`[${taskName}] Validated ${msg.getFrom().index} -> ${this.params.partyID().index}`);
			const [ok, err] = party.update(msg);
			if (!ok || err) {
				return [false, err];
			}

			this.ok[msg.getFrom().index] = true;
			return [true, null];
		} catch (error) {
			return [false, new TssError(error instanceof Error ? error.message : String(error))];
		}
	}

	public parseWireMessage(wireBytes: Uint8Array, from: PartyID, isBroadcast: boolean): ParsedMessage | TssError {
		try {
			const message = JSON.parse(Buffer.from(wireBytes).toString());
			return {
				getFrom: () => from,
				content: () => message,
				isBroadcast: isBroadcast,
				wireBytes: wireBytes
			};
		} catch (error) {
			return new TssError(error instanceof Error ? error.message : String(error));
		}
	}

	public validateMessage(msg: ParsedMessage): boolean {
		if (!msg || typeof msg.getFrom !== 'function') {
			return false;
		}

		const from = msg.getFrom();
		if (!from || typeof from.index !== 'number') {
			return false;
		}

		if (from.index >= this.params.totalParties) {
			return false;
		}

		return true;
	}

	protected wrapError(err: Error, ...culprits: PartyID[]): TssError {
		return new TssError(`${err.message} - culprits: ${culprits.map(c => c.index).join(', ')}`);
	}

	protected resetOK(): void {
		this.ok.fill(false);
	}

	public toString(): string {
		const waiting = this.ok
			.map((ok, i) => !ok ? this.params.parties[i] : null)
			.filter(p => p !== null);
		return `waiting for ${waiting.join(', ')}`;
	}

	public canProceed(): boolean {
		return this.ok.every(ok => ok);
	}

	public waitingFor(): PartyID[] {
		return this.ok
			.map((ok, i) => !ok ? this.params.parties[i] : null)
			.filter((p): p is PartyID => p !== null);
	}
}

export { BaseParty, Params };