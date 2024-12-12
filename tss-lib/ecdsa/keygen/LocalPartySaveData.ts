import BN from 'bn.js';
import { LocalPreParams } from './LocalPreParams';
import { Shares } from '../../crypto/VSS';
import { ProofFac } from '../../crypto/FACProof';
import { ProofMod } from '../../crypto/MODProof';
import { ECPoint } from '../../crypto/ECPoint';

export class LocalPartySaveData {
    // Required params
    public localPreParams?: LocalPreParams;
    public shareID: BN;
    public ks: BN[];

    // ECDSA keys
    public xi?: BN;
    public ecdsaPub?: ECPoint;
    public bigXj: ECPoint[];

    // Paillier keys
    public paillierSK: any;  // TODO: Add proper PaillierSecretKey type
    public paillierPKs: any[];  // TODO: Add proper PaillierPublicKey type

    // ZK proof params
    public NTildej: BN[];
    public H1j: BN[];
    public H2j: BN[];

    // Precomputed values
    public Alpha: BN;
    public Beta: BN;
    public P: BN;
    public Q: BN;

    // VSS shares and proofs
    public shares: Shares;
    public facProofs: ProofFac[];
    public deCommitPolyGs: BN[];
    public modProofs: ProofMod[];

    constructor(partyCount: number) {
        // Initialize required params
        this.shareID = new BN(0);
        this.ks = new Array(partyCount);

        // Initialize arrays
        this.bigXj = new Array(partyCount);
        this.paillierPKs = new Array(partyCount);
        this.NTildej = new Array(partyCount);
        this.H1j = new Array(partyCount);
        this.H2j = new Array(partyCount);

        // Initialize ZK proof params
        this.Alpha = new BN(0);
        this.Beta = new BN(0);
        this.P = new BN(0);
        this.Q = new BN(0);

        // Initialize proofs arrays
        this.facProofs = new Array(partyCount);
        this.deCommitPolyGs = new Array(partyCount);
        this.modProofs = new Array(partyCount);

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