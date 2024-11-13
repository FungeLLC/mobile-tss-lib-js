import BN from 'bn.js';
import { LocalPreParams } from './LocalPreParams';

class LocalPartySaveData {
	public localPreParams?: LocalPreParams;
	public shareID: BN = new BN(0);
	public ks: BN[];

	constructor(partyCount: number) {
		this.ks = new Array(partyCount).fill(new BN(0));
	}

	public originalIndex(): number {
		const ki = this.shareID;
		for (let j = 0; j < this.ks.length; j++) {
			if (this.ks[j].cmp(ki) === 0) {
				return j;
			}
		}
		throw new Error('a party index could not be recovered from Ks');
	}
}

export { LocalPartySaveData };