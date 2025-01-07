// rounds.ts
import { Parameters, PartyID, Round, MessageFromTss } from './interfaces';
import { LocalPartySaveData } from './LocalPartySaveData';
import { LocalTempData } from './LocalTempData';
import { TssError } from '../../common/TssError';
import { SHA512_256i } from '../../common/Hash';
import BN from 'bn.js';

export const TaskName = "eddsa-keygen";

export abstract class BaseRound {
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

	protected resetOK(): void {
		this.ok.fill(false);
	}

	protected async getSSID(): Promise<Buffer> {
		const ssidList = [
			this.params.ecParams.p,
			this.params.ec.n,
			this.params.ec.g.x,
			this.params.ec.g.y,
			...this.params.parties.map(p => p.keyInt()),
			new BN(this.number),
			this.temp.ssidNonce
		];

		const ssid = SHA512_256i(...ssidList);
		
		return Buffer.from(ssid.toArray());
	}
}

import { Round1 } from './Round1';
import { Round2 } from './Round2';
import { Round3 } from './Round3';
import { Round4 } from './Round4';

export {
	Round1,
	Round2,
	Round3,
	Round4
};