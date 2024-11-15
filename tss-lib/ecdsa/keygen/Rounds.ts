import { Parameters, PartyID, Round, MessageFromTss, ParsedMessage } from './interfaces';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from './TssError';
import { SHA512_256i } from '../../common/Hash';
import BN from 'bn.js';


import { Round1 as Round1Implementation } from './Round1';
import { Round2 as Round2Implementation } from './Round2';
import { Round3 as Round3Implementation } from './Round3';
import { Round4 as Round4Implementation } from './Round4';

const TaskName = "ecdsa-keygen";

class BaseRound {
	protected ok: boolean[];
	protected started: boolean = false;
	protected number: number = 0;

	constructor(
		protected params: Parameters,
		protected data: LocalPartySaveData,
		protected temp: LocalTempData,
		protected out: (msg: MessageFromTss) => void,
		protected end: (data: LocalPartySaveData) => void,
	) {
		this.ok = new Array(params.parties.length).fill(false);
	}

	public async start(): Promise<TssError | null> {
		if (this.started) {
			return new TssError('round already started');
		}
		this.started = true;
		this.resetOK();
		return null;
	}

	public roundNumber(): number {
		return this.number;
	}

	public canProceed(): boolean {
		if (!this.started) {
			return false;
		}
		return this.ok.every(ok => ok);
	}

	public waitingFor(): PartyID[] {
		const Ps = this.params.parties;
		return this.ok.reduce((ids: PartyID[], ok, j) => {
			if (!ok) {
				ids.push(Ps[j]);
			}
			return ids;
		}, []);
	}

	protected wrapError(err: Error, ...culprits: PartyID[]): TssError {
		return new TssError(
			`${err.message} (task: ${TaskName}, round: ${this.number}, party: ${this.params.partyID()}, culprits: ${culprits.join(',')})`
		);
	}

	protected resetOK(): void {
		this.ok.fill(false);
	}

	protected async getSSID(): Promise<Buffer> {
		const ec = this.params.ec;
		const ssidList = [
			ec.p,
			ec.n,
			ec.g.x,
			ec.g.y,
			...this.params.parties.map(p => p.keyInt()),
			new BN(this.number),
			this.temp.ssidNonce
		];

		const ssid = SHA512_256i(...ssidList);
		return Buffer.from(ssid.toArray());
	}
}

class Round1 extends BaseRound implements Round {
	constructor(...args: ConstructorParameters<typeof BaseRound>) {
		super(...args);
		this.number = 1;
		
	}
	update(msg: ParsedMessage): [boolean, TssError | null] {
		throw new Error('Method not implemented.');
	}
}

class Round2 extends Round1 {
	constructor(...args: ConstructorParameters<typeof BaseRound>) {
		super(...args);
		this.number = 2;
	}
}

class Round3 extends Round2 {
	constructor(...args: ConstructorParameters<typeof BaseRound>) {
		super(...args);
		this.number = 3;
	}
}

class Round4 extends Round3 {
	constructor(...args: ConstructorParameters<typeof BaseRound>) {
		super(...args);
		this.number = 4;
	}
}

export {
	BaseRound,
	Round1Implementation as Round1,
	Round2Implementation as Round2,
	Round3Implementation as Round3,
	Round4Implementation as Round4,
	TaskName
};