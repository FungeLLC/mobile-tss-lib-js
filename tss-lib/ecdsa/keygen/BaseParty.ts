import { ParsedMessage, PartyID } from './interfaces';
import { TssError } from './TssError';

interface Params {
	totalParties: number;
}

class BaseParty {
	public params: Params;

	constructor(params: Params) {
		this.params = params;
	}
	public start(party: any, taskName: string): TssError | null {
		try {
			// Implement the logic to start the base party
			party.firstRound().start();
			return null;
		} catch (error) {
			if (error instanceof Error) {
				return new TssError(error.message);
			}
			return null;
		}
	}

	public update(party: any, msg: ParsedMessage, taskName: string): [boolean, TssError | null] {
		try {
			// Implement the logic to update the base party
			const [ok, err] = party.update(msg);
			if (!ok || err) {
				return [false, err];
			}
			return [true, null];
		} catch (error) {
			if (error instanceof Error) {
				return [false, new TssError(error.message)];
			}
			return [false, null];
		}
	}

	public parseWireMessage(wireBytes: Uint8Array, from: PartyID, isBroadcast: boolean): ParsedMessage | TssError {
		try {
			// Implement the logic to parse wire message
			const message = JSON.parse(Buffer.from(wireBytes).toString('utf-8'));
			return {
				getFrom: () => from,
				content: () => message,
			} as ParsedMessage;
		} catch (error) {
			if (error instanceof Error) {
				return new TssError(error.message);
			}
			return new TssError('Error parsing	wire message');
		}
	}

	public validateMessage(msg: ParsedMessage): [boolean, TssError | null] {
		// Check if the message is valid
		if (!msg || typeof msg.content !== 'function' || typeof msg.getFrom !== 'function') {
			return [false, new TssError('Invalid message format')];
		}

		// Check if the sender information is valid
		const from = msg.getFrom();
		if (!from || typeof from.index !== 'number') {
			return [false, new TssError('Invalid sender information')];
		}

		// Check if the message content is valid
		const content = msg.content();
		if (!content) {
			return [false, new TssError('Message content is empty')];
		}

		// Check that the message's "from index" will fit into the array
		if (this.params.totalParties - 1 < from.index) {
			return [false, new TssError(`received msg with a sender index too great (${this.params.totalParties} <= ${from.index})`)];
		}

		return [true, null];
	}

	public toString(): string {
		return 'BaseParty';
	}
}

export { BaseParty };