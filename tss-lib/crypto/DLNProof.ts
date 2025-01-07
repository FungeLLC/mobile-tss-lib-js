import BN from 'bn.js';
import winston from 'winston';
import { testLogger as defaultLogger } from '../common/Logger';

import ModInt from '../common/ModInt';
import { SHA512_256i } from '../common/Hash';
import { getRandomPositiveInt } from '../common/Random';
import crypto from 'crypto';
import { RandomBytesProvider } from '../common/Types';

const Iterations = 128;

// export interface RandomBytesProvider {
// 	randomBytes: (size: number) => Buffer;
// }

// dlnproof.ts
/**
 * Represents a Discrete Logarithm Non-membership Proof (DLN Proof).
 * 
 * This class implements a zero-knowledge proof system that demonstrates knowledge of a secret value x
 * in the equation h2 = h1^x mod N, without revealing x. The proof works over a composite modulus N
 * which is the product of two safe primes p and q.
 * 
 * The proof system uses a sigma protocol with parallel repetitions to achieve the desired security
 * properties, using SHA512/256 for challenge generation.
 * 
 * @remarks
 * - All arithmetic operations are performed modulo N
 * - The proof consists of two main components:
 *   1. Alpha array (commitment values)
 *   2. T array (responses)
 * - Both arrays must have equal length
 * 
 * @example
 * ```typescript
 * // Generate a new proof
 * const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N);
 * 
 * // Verify the proof
 * const isValid = proof.verify(h1, h2, N);
 * ```
 * 
 * @see {@link newDLNProof} for proof generation
 * @see {@link verify} for proof verification
 * @see {@link serialize} for proof serialization
 * @see {@link unmarshalDLNProof} for proof deserialization
 */
export class DLNProof {
	private validateArrayLengths(alpha: BN[], t: BN[]) {
		if (alpha.length !== t.length) {
			throw new Error('Alpha and T arrays must have the same length');
		}
	}

	constructor(
		private Alpha: BN[],
		private T: BN[]
	) {
		this.validateArrayLengths(Alpha, T);
	}

	public getAlpha(): BN[] {
		return this.Alpha;
	}

	public getT(): BN[] {
		return this.T;
	}

	public getXValues(): BN[] {
		return this.Alpha;
	}

	/**
	 * Marshals a Discrete Log N-Proof (DLNProof) into a Buffer.
	 * 
	 * This function combines the Alpha and T arrays from the proof into a single Buffer.
	 * Each element from both arrays is converted to a big-endian 32-byte representation.
	 * The resulting buffer contains all Alpha elements followed by all T elements.
	 *
	 * @param proof - The DLNProof object containing Alpha and T arrays to be marshaled
	 * @returns A Buffer containing the serialized proof data where:
	 *          - First half contains Alpha values in sequence
	 *          - Second half contains T values in sequence
	 *          - Each value is stored as a 32-byte big-endian number
	 */
	public serialize(): Buffer[] {
		// Create two arrays - one for Alpha and one for T
		const result: Buffer[] = [];

		// Add Alpha values
		for (let i = 0; i < Iterations; i++) {
			result.push(this.Alpha[i].toArrayLike(Buffer));
		}

		// Add T values 
		for (let i = 0; i < Iterations; i++) {
			result.push(this.T[i].toArrayLike(Buffer));
		}

		return result;
	}
	

	/**
	 * Unmarshals a buffer into a DLNProof object
	 * @param buf - Buffer containing the serialized DLNProof data. Expected to contain two equal-length arrays of 32-byte values
	 * @returns A new DLNProof instance constructed from the unmarshaled alpha and t arrays
	 * @remarks The buffer is expected to be formatted as a concatenation of two arrays:
	 * - First half: Array of alpha values, each 32 bytes
	 * - Second half: Array of t values, each 32 bytes
	 * Total buffer length must be divisible by 64 (2 * 32) bytes
	 */
	public static unmarshalDLNProof(bzs: Buffer[]): DLNProof {
		// Check expected length
		if (bzs.length !== 2 * Iterations) {
			throw new Error(`Expected ${2 * Iterations} byte arrays but got ${bzs.length}`);
		}

		// Convert to BNs
		const bis = bzs.map(bz => new BN(bz));

		// Split into Alpha and T arrays
		const alpha = bis.slice(0, Iterations);
		const t = bis.slice(Iterations, 2 * Iterations);

		// Create new proof
		return new DLNProof(alpha, t);
	}

	/**
	 * Random bytes generation utilities.
	 * @property {Object} rand - Random bytes generator object
	 * @property {Function} rand.randomBytes - Generates cryptographically strong random bytes
	 * @param {number} size - The number of bytes to generate
	 * @returns {Buffer} A buffer containing the random bytes
	 */
	public rand = {
		randomBytes: (size: number) => crypto.randomBytes(size)
	};


 // NewDLNProof generates a new discrete logarithm proof.
// h1, h2: group elements
// x: secret exponent
// p, q: safe primes
// N: modulus
// rand: random source
	

	/**
	 * Creates a new DLN (Discrete Logarithm over N) Proof.
	 * This implements a zero-knowledge proof for showing knowledge of x in h2 = h1^x mod N
	 * without revealing x.
	 * 
	 * @param h1 - Base element in the proof
	 * @param h2 - Result element in the proof (h2 = h1^x mod N)
	 * @param x - Secret exponent to prove knowledge of
	 * @param p - Prime factor of N
	 * @param q - Prime factor of N
	 * @param N - Public modulus (N = p*q)
	 * @param logger
	 * @returns A DLN proof consisting of commitment values (alpha) and responses (t)
	 *
	 * @remarks
	 * The proof follows a sigma protocol with parallel repetitions to achieve 
	 * desired security properties. It uses SHA512/256 for challenge generation.
	 */
	public static newDLNProof(h1: BN, h2: BN, x: BN, p: BN, q: BN, N: BN, logger: winston.Logger = defaultLogger): DLNProof {
		const pMulQ = p.mul(q);
		const modN = new ModInt(N);
		const modPQ = new ModInt(pMulQ);

		if (N.lte(new BN(1)) || N.isNeg()) {
			throw new Error('Invalid N: N <= 1');
		}



		logger.debug('Generating DLN proof', {
			h1: h1.toString(16),
			h2: h2.toString(16),
			N: N.toString(16)
		});

		// Match Go's random number generation
		const a: BN[] = new Array(Iterations);
		const alpha: BN[] = new Array(Iterations);

		for (let i = 0; i < Iterations; i++) {
			// Match Go's GetRandomPositiveInt

			let cnt = 0;

			// Generate a random number in range (0, pMulQ)
			a[i] = getRandomPositiveInt(pMulQ) || new BN(0);
			if (a[i].isZero()) {
				throw new Error('Failed to generate non-zero random number');
			}

			// Use exp instead of modPow to match Go
			alpha[i] = modN.pow(h1, a[i]);
			logger.debug(`Generated a[${i}] and alpha[${i}]`, {
				a: a[i].toString(16),
				alpha: alpha[i].toString(16)
			});
		}


		const msg = [h1, h2, N, ...alpha];
		const c = SHA512_256i(...msg);
		if (!c) {
			throw new Error('Failed to generate challenge');
		}

		const t: BN[] = new Array(Iterations);
		const cIBI = new BN(0);  // Create and reuse like Go

		for (let i = 0; i < Iterations; i++) {
			// Match Go's bit extraction and Int64 conversion exactly
			const cI = c.testn(i) ? 1 : 0;
			cIBI.setn(0, cI);  // Reuse BN instance like Go's SetInt64

			// Match Go's modular arithmetic exactly
			const mulResult = modPQ.mul(cIBI, x);
			t[i] = modPQ.add(a[i], mulResult);
		}

		return new DLNProof(alpha, t);
	}

	/**
	 * Verifies the discrete logarithm proof.
	 * @param h1 - First group element.
	 * @param h2 - Second group element.
	 * @param N - Modulus.
	 * @returns True if the proof is valid, false otherwise.
	 */

	/**
	 * Verifies a discrete logarithm non-membership proof.
	 * 
	 * @param h1 - First base element of the proof
	 * @param h2 - Second base element of the proof
	 * @param N - Modulus for the proof verification
	 * 
	 * @returns boolean indicating if the proof is valid
	 * 
	 * The verification process includes:
	 * 1. Checking if inputs are non-zero
	 * 2. Validating h1 and h2 are in proper range (1 < h1,h2 < N)
	 * 3. Ensuring h1 and h2 are different
	 * 4. Verifying Alpha and T array elements are in proper range
	 * 5. Computing challenge c using SHA512_256i
	 * 6. Verifying the proof equations for each Alpha[i] and T[i]
	 * 
	 * @throws None - Returns false instead of throwing errors
	 */
	public verify(h1: BN, h2: BN, N: BN, logger: winston.Logger = defaultLogger): boolean {
		if (N.lte(new BN(1))) {
			logger.debug('Invalid N: N <= 1');
			return false;
		}

		const one = new BN(1);
		const modN = new ModInt(N);

		logger.debug('Verifying DLN proof', {
			h1: h1.toString(16),
			h2: h2.toString(16),
			N: N.toString(16)
		});

		// Input validation (keep existing validation code)
		const h1Mod = h1.umod(N);
		const h2Mod = h2.umod(N);
		if (h1Mod.cmp(one) <= 0 || h1Mod.cmp(N) >= 0) {
			logger.debug('Invalid h1: not in range (1,N)');
			return false;
		}
		if (h2Mod.cmp(one) <= 0 || h2Mod.cmp(N) >= 0) {
			logger.debug('Invalid h2: not in range (1,N)');
			return false;
		}
		if (h1Mod.eq(h2Mod)) {
			logger.debug('Invalid inputs: h1 = h2');
			return false;
		}

		// Alpha and T validation (keep existing validation code)
		for (let i = 0; i < Iterations; i++) {
			if (!this.Alpha[i] || !this.T[i]) {
				logger.debug(`Missing Alpha[${i}] or T[${i}]`);
				return false;
			}
			const alphaMod = modN.reduce(this.Alpha[i]);
			const tMod = modN.reduce(this.T[i]);

			// logger.debug(`Iteration ${i}:`, {
			// 	alpha: this.Alpha[i].toString(16),
			// 	t: this.T[i].toString(16),
			// 	alphaMod: alphaMod.toString(16),
			// 	tMod: tMod.toString(16)
			// });

			if (alphaMod.cmp(one) <= 0 || alphaMod.cmp(N) >= 0) {
				logger.debug(`Invalid Alpha[${i}]: not in range (1,N)`);
				return false;
			}
			if (tMod.cmp(one) <= 0 || tMod.cmp(N) >= 0) {
				logger.debug(`Invalid T[${i}]: not in range (1,N)`);
				return false;
			}
		}

		// Compute challenge exactly as Go does
		const msg = [h1, h2, N, ...this.Alpha];
		const c = SHA512_256i(...msg);

		if(!c) {
			winston.error('Failed to generate challenge');
			return false;
		}

		// Verification loop - match Go's implementation exactly
		for (let i = 0; i < Iterations; i++) {
			// Get challenge bit exactly as Go does
			const cI = c.testn(i) ? new BN(1) : new BN(0);

			// Compute both sides of equation
			const h1ExpTi = modN.pow(h1, this.T[i]);
			const h2ExpCi = modN.pow(h2, cI);
			const alphaIMulH2ExpCi = modN.mul(this.Alpha[i], h2ExpCi);

			// Apply modular reduction to both sides
			const lhs = modN.reduce(h1ExpTi);
			const rhs = modN.reduce(alphaIMulH2ExpCi);

			// Compare values
			if (!lhs.eq(rhs)) {
				logger.error(`Verification failed at iteration ${i}`);
				logger.error(`h1^T[i] mod N = ${lhs.toString(16)}`);
				logger.error(`(Alpha[i] * h2^cI) mod N = ${rhs.toString(16)}`);
				return false;
			}
		}
		return true;
	}
}