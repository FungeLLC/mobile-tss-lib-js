import BN from 'bn.js';
import { RejectionSample } from '../common/hash_utils';
import { SHA512_256i_TAGGED } from '../common/Hash';
import ModInt from '../common/ModInt';
import { getRandomPositiveInt, getRandomPositiveRelativelyPrimeInt } from '../common/Random';
import sqrt from 'bn-sqrt';

export class ProofFac {
  // Proof values similar to Go
  public P: BN;
  public Q: BN;
  public A: BN;
  public B: BN;
  public T: BN;
  public Sigma: BN;
  public Z1: BN;
  public Z2: BN;
  public W1: BN;
  public W2: BN;
  public V: BN;

  constructor(
    P: BN, Q: BN, A: BN, B: BN, T: BN,
    Sigma: BN, Z1: BN, Z2: BN, W1: BN,
    W2: BN, V: BN
  ) {
    this.P = P; this.Q = Q; this.A = A; this.B = B;
    this.T = T; this.Sigma = Sigma; this.Z1 = Z1; 
    this.Z2 = Z2; this.W1 = W1; this.W2 = W2; 
    this.V = V;
  }

  public static newProof(
    context: Buffer,
    ec: any,
    N0: BN,
    NCap: BN,
    s: BN,
    t: BN,
    N0p: BN,
    N0q: BN,
  ): ProofFac {
    // Create ModInt instances for efficient modular arithmetic
    const modNCap = new ModInt(NCap);

    // Match Go's curve parameter calculations
    const q = new BN(ec.n);
    const q3 = q.mul(q).mul(q);
    const qNCap = q.mul(NCap);
    const qN0NCap = qNCap.mul(N0);
    const q3NCap = q3.mul(NCap);
    const q3N0NCap = q3NCap.mul(N0);
    const sqrtN0 = sqrt(N0);
    const q3SqrtN0 = q3.mul(sqrtN0);


    //output all the values
    console.log('q:', q);
    console.log('q3:', q3);
    console.log('qNCap:', qNCap);
    console.log('qN0NCap:', qN0NCap);
    console.log('q3NCap:', q3NCap);
    console.log('q3N0NCap:', q3N0NCap);
    console.log('sqrtN0:', sqrtN0);
    console.log('q3SqrtN0:', q3SqrtN0);
    

    // Generate random values using same ranges as Go
    const alpha = getRandomPositiveInt(q3SqrtN0);
    const beta = getRandomPositiveInt(q3SqrtN0);
    const mu = getRandomPositiveInt(qNCap);
    const nu = getRandomPositiveInt(qNCap);
    const sigma = getRandomPositiveInt(qN0NCap);
    const r = getRandomPositiveRelativelyPrimeInt(q3N0NCap);
    const x = getRandomPositiveInt(q3NCap);
    const y = getRandomPositiveInt(q3NCap);

    // Compute values using ModInt for efficiency
    const P = modNCap.mul(
      modNCap.pow(s, N0p),
      modNCap.pow(t, mu)
    );

    const Q = modNCap.mul(
      modNCap.pow(s, N0q),
      modNCap.pow(t, nu)
    );

    const A = modNCap.mul(
      modNCap.pow(s, alpha),
      modNCap.pow(t, x)
    );

    const B = modNCap.mul(
      modNCap.pow(s, beta),
      modNCap.pow(t, y)
    );

    const T = modNCap.mul(
      modNCap.pow(Q, alpha),
      modNCap.pow(t, r)
    );

    // Match Go's hash calculation and rejection sampling
    const eHash = SHA512_256i_TAGGED(
      context, N0, NCap, s, t, P, Q, A, B, T, sigma
    );
    const e = RejectionSample(q, eHash);

    // Calculate final values
    const z1 = e.mul(N0p).add(alpha);
    const z2 = e.mul(N0q).add(beta);
    const w1 = e.mul(mu).add(x);
    const w2 = e.mul(nu).add(y);

    // v:= new (big.Int).Mul(nu, N0p)
    // v = new (big.Int).Sub(sigma, v)
    // v = new (big.Int).Mul(e, v)
    // v = new (big.Int).Add(v, r)

    const v = e.mul(sigma.sub(nu.mul(N0p))).add(r);

    return new ProofFac(P, Q, A, B, T, sigma, z1, z2, w1, w2, v);
  }

  /**
   * Matches the Go Verify() approach:
   *  1) Check range for Z1, Z2
   *  2) Create challenge e
   *  3) Check exponent equality in three separate conditions
   */
  public verify(
    Session: Buffer,
    ec: any,    // elliptic curve with ec.n
    N0: BN,
    NCap: BN,
    s: BN,
    t: BN
  ): boolean {
    // Basic validations
    if (!this.validateBasic()) return false;
    if (!ec || !N0 || !NCap || !s || !t) return false;
    if (N0.lte(new BN(1))) return false;

    // 1. Range checks (like Go's q3*Sqrt(N0))
    const q: BN = new BN(ec.n);
    const q3 = q.mul(q).mul(q);
    const sqrtN0 = sqrt(N0); // or new BN(N0.toString()).sqrt();
    const q3SqrtN0 = q3.mul(sqrtN0);

    // In Go: IsInInterval(Z1, q3SqrtN0) etc.
    if (this.Z1.gte(q3SqrtN0) || this.Z2.gte(q3SqrtN0)) {
      return false;
    }
    
    // 2. Create challenge e
    // eHash = SHA512_256i_TAGGED(
    //   Session, N0, NCap, s, t, P, Q, A, B, T, Sigma
    // )
    const eHash = SHA512_256i_TAGGED(
      Session,
      N0, NCap, s, t,
      this.P, this.Q, this.A, this.B, this.T, this.Sigma
    );
    if (!eHash) {
      return false;
    }
    const e = RejectionSample(q, eHash);

    // 3. Exponent equality checks
    // Go logic (three blocks):
    //  LHS1 = s^Z1 * t^W1
    //  RHS1 = A * (P^e)
    //  ...
    const modNCap = new ModInt(NCap);
    
    // Check #1
    const lhs1 = modNCap.mul(
      modNCap.exp(s, this.Z1),
      modNCap.exp(t, this.W1)
    );
    const rhs1 = modNCap.mul(
      this.A,
      modNCap.exp(this.P, e)
    );
    if (lhs1.cmp(rhs1) !== 0) {
      return false;
    }

    // Check #2
    const lhs2 = modNCap.mul(
      modNCap.exp(s, this.Z2),
      modNCap.exp(t, this.W2)
    );
    const rhs2 = modNCap.mul(
      this.B,
      modNCap.exp(this.Q, e)
    );
    if (lhs2.cmp(rhs2) !== 0) {
      return false;
    }

    // Check #3
    // R = s^N0 * t^Sigma, then check Q^Z1 * t^V == T * (R^e)
    // (In Go code, it’s stored as LHS vs RHS with R^e)
    const R = modNCap.mul(
      modNCap.exp(s, N0),
      modNCap.exp(t, this.Sigma)
    );
    const lhs3 = modNCap.mul(
      modNCap.exp(this.Q, this.Z1),
      modNCap.exp(t, this.V)
    );
    const rhs3 = modNCap.mul(
      this.T,
      modNCap.exp(R, e)
    );
    if (lhs3.cmp(rhs3) !== 0) {
      return false;
    }

    return true;
  }

  // Basic "nil" checks, like Go's ValidateBasic()
  public validateBasic(): boolean {
    return (
      this.P && this.Q && this.A && 
      this.B && this.T && this.Sigma && 
      this.Z1 && this.Z2 && this.W1 && 
      this.W2 && this.V
    ) ? true : false;
  }
}