import BN from 'bn.js';
import { LocalPreParams } from './LocalPreParams';
import { Shares } from '../../crypto/VSS';
import { ECPoint } from '../../crypto/ECPoint';

export class LocalPartySaveData {
    // Required params
    public localPreParams?: LocalPreParams;
    public shareID: BN;
    public ks: BN[];

    // EdDSA keys
    public xi?: BN;
    public eddsaPub?: ECPoint;
    public bigXj: ECPoint[];

    // VSS shares
    public shares: Shares;
    public deCommitPolyGs: BN[];

    constructor(partyCount: number) {
        // Initialize required params
        this.shareID = new BN(0);
        this.ks = new Array(partyCount);

        // Initialize arrays
        this.bigXj = new Array(partyCount);
        this.deCommitPolyGs = new Array(partyCount);

        // Initialize VSS shares
        this.shares = [];
    }

    public originalIndex(): number {
        const ki = this.shareID;
        for (let j = 0; j < this.ks.length; j++) {
            if (this.ks[j].eq(ki)) {
                return j;
            }
        }
        throw new Error("a party index could not be recovered from Ks");
    }
}