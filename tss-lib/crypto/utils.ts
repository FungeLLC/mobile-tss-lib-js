import BN from 'bn.js';
import { isProbablyPrime } from '../common/Random'


/**
 * Like Go's common.GetRandomGeneratorOfTheQuadraticResidue
 * Finds a generator g in [1, N-1] such that gcd(g, N) = 1
 * and ensures g is a quadratic residue modulo N by squaring.
 */
function getRandomGeneratorOfTheQuadraticResidue(rand: () => Buffer, N: BN): BN {
  while (true) {
    // For demonstration, get random bytes the size of N
    const candidate = new BN(rand());
    if (candidate.isZero() || candidate.gte(N)) {
      continue;
    }
    // gcd must be 1
    if (candidate.gcd(N).eqn(1)) {
      // Square to ensure it is a quadratic residue
      return candidate.pow(new BN(2)).umod(N);
    }
  }
}

/**
 * GenerateNTildei replicates the Go code:
 *
 *   func GenerateNTildei(rand io.Reader, safePrimes [2]*big.Int) (NTildei, h1i, h2i *big.Int, err error)
 *
 * 1) Ensure the given primes are non-nil and likely prime
 * 2) Multiply them to form N
 * 3) Generate h1, h2 as random generators of the quadratic residue
 */
export function GenerateNTildei(
  rand: () => Buffer,
  safePrimes: [BN, BN]
): [BN, BN, BN] {
  const [p, q] = safePrimes;

  if (!p || !q) {
    throw new Error(`GenerateNTildei: needs two primes, got ${safePrimes}`);
  }
  if (!isProbablyPrime(p) || !isProbablyPrime(q)) {
    throw new Error('GenerateNTildei: expected two primes');
  }

  // N = p * q
  const N = p.mul(q);

  // h1, h2: random quadratic residues mod N
  const h1 = getRandomGeneratorOfTheQuadraticResidue(rand, N);
  const h2 = getRandomGeneratorOfTheQuadraticResidue(rand, N);

  return [N, h1, h2];
}