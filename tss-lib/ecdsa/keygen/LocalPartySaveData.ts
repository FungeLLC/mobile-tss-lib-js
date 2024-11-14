import BN from 'bn.js';
import { LocalPreParams } from './LocalPreParams';
import { Shares } from './interfaces';
import { ProofFac } from '../../crypto/facproof';
import { ProofMod } from '../../crypto/modproof';

class LocalPartySaveData {
    public localPreParams?: LocalPreParams;
    public combinedShares: Shares;

    public shareID: BN = new BN(0);
    public ks: BN[];

    paillierPKs: any;
    NTildej: any;
    H1j: any;
    H2j: any;
    paillierSK: any;

	shares: Shares;

	facProofs: ProofFac[];

	deCommitPolyGs: any[];

	modProofs: ProofMod[];

    constructor(partyCount: number) {
        this.combinedShares = new Shares();
        this.ks = new Array(partyCount).fill(new BN(0));
        this.paillierPKs = new Array(partyCount);
        this.NTildej = new Array(partyCount);
        this.H1j = new Array(partyCount);
        this.H2j = new Array(partyCount);

		this.shares = new Shares();
		this.facProofs = new Array(partyCount);
		this.deCommitPolyGs = new Array(partyCount);
		this.modProofs = new Array(partyCount);
		
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