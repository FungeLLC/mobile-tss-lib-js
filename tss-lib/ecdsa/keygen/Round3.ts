import { KeygenParams, LocalPartySaveData, LocalTempData, MessageFromTss, Round, ParsedMessage } from './interfaces';
import { TssError } from './TSSError';

class Round3 implements Round {
	constructor(
		private params: KeygenParams,
		private data: LocalPartySaveData,
		private temp: LocalTempData,
		private out: (msg: MessageFromTss) => void,
		private end: (data: LocalPartySaveData) => void
	) { }

	public start(): TssError | null {
		try {
			// Implement the logic for Round3 start
			// ...

			return null;
		} catch (error) {
			return new TssError(error);
		}
	}

	public update(msg: ParsedMessage): [boolean, TssError | null] {
		const fromPIdx = msg.getFrom().index;

		switch (msg.content().constructor) {
			case 'KGRound3Message':
				this.temp.kgRound3Messages[fromPIdx] = msg;
				break;
			default:
				return [false, new TssError(`unrecognised message type: ${msg.content().constructor}`)];
		}

		// Check if all messages are received
		if (this.temp.kgRound3Messages.every(m => m !== undefined)) {
			this.endRound();
		}

		return [true, null];
	}

	private endRound(): void {
		// Process the received messages
		// ...

		// Move to the next round or finish
		this.end(this.data);
	}
}

export { Round3 };