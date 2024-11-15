import BN from 'bn.js';
import crypto from 'crypto';

const primeTestN = 30;
const two = new BN(2);
const one = new BN(1);
const three = new BN(3);

// Small primes list for optimization
const smallPrimes = [
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53
];

const smallPrimesProduct = new BN('16294579238595022365');

function millerRabinTest(n: BN, a: BN): boolean {
	if (n.isEven()) return false;

	// Write n-1 as d*2^r
	let d = n.subn(1);
	let r = 0;
	while (d.isEven()) {
		d = d.shrn(1);
		r++;
	}

	// Witness loop
	let x = a.toRed(BN.mont(n)).redPow(d);
	if (x.eq(new BN(1).toRed(BN.mont(n))) || x.eq(n.subn(1).toRed(BN.mont(n)))) {
		return true;
	}

	for (let i = 0; i < r - 1; i++) {
		x = x.redSqr();
		if (x.eq(n.subn(1).toRed(BN.mont(n)))) {
			return true;
		}
		if (x.eq(new BN(1).toRed(BN.mont(n)))) {
			return false;
		}
	}
	return false;
}

function isProbablePrime(n: BN): boolean {
	if (n.ltn(2)) return false;
	if (n.eq(new BN(2))) return true;
	if (n.isEven()) return false;

	// Test against small primes first
	if (!n.gcd(smallPrimesProduct).eq(new BN(1))) {
		return false;
	}

	// Miller-Rabin test with first few prime numbers as bases
	const witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
	for (let i = 0; i < Math.min(witnesses.length, primeTestN); i++) {
		if (!millerRabinTest(n, new BN(witnesses[i]))) {
			return false;
		}
	}

	return true;
}

export function probablyPrime(prime: BN | null): boolean {
	return prime !== null && isProbablePrime(prime);
}


function getSafePrime(p: BN): BN {
	return p.mul(two).add(one);
}


export class GermainSafePrime {
	constructor(
		private q: BN, // prime
		private p: BN  // safePrime = 2q + 1
	) { }

	public prime(): BN {
		return this.q;
	}

	public safePrime(): BN {
		return this.p;
	}

	public validate(): boolean {
		return probablyPrime(this.q) &&
			getSafePrime(this.q).eq(this.p) &&
			probablyPrime(this.p);
	}
}


export class SafePrimeError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'SafePrimeError';
	}
}

export async function getRandomSafePrimesConcurrent(
	bitLen: number,
	numPrimes: number,
	concurrency: number
): Promise<GermainSafePrime[]> {
	if (bitLen < 6) {
		throw new SafePrimeError('safe prime size must be at least 6 bits');
	}
	if (numPrimes < 1) {
		throw new SafePrimeError('numPrimes should be > 0');
	}

	const primes: GermainSafePrime[] = [];
	const workers: Promise<GermainSafePrime>[] = [];

	for (let i = 0; i < concurrency; i++) {
		workers.push(generateSafePrime(bitLen));
	}

	while (primes.length < numPrimes) {
		const prime = await Promise.race(workers);
		primes.push(prime);

		// Replace completed worker
		const completePromiseIndex = workers.findIndex((w) => Promise.race([w]).then(() => true, () => false));
		if (completePromiseIndex !== -1) {
			workers[completePromiseIndex] = generateSafePrime(bitLen);
		}
	}

	return primes;
}

async function generateSafePrime(pBitLen: number): Promise<GermainSafePrime> {
	const qBitLen = pBitLen - 1;

	while (true) {
		// Generate random candidate
		const bytes = crypto.randomBytes(Math.ceil(qBitLen / 8));

		// Set appropriate bits
		const b = qBitLen % 8 || 8;
		bytes[0] &= (1 << b) - 1;

		if (b >= 2) {
			bytes[0] |= 3 << (b - 2);
		} else {
			bytes[0] |= 1;
			if (bytes.length > 1) {
				bytes[1] |= 0x80;
			}
		}

		// Make odd
		bytes[bytes.length - 1] |= 1;

		const q = new BN(bytes);

		// Check divisibility by small primes
		if (!isPrimeCandidate(q)) {
			continue;
		}

		// Check if q ≡ 1 (mod 3)
		if (q.mod(three).eq(one)) {
			continue;
		}

		// Generate and check p = 2q + 1
		const p = getSafePrime(q);
		if (!isPrimeCandidate(p)) {
			continue;
		}

		// Final primality tests
		if (isProbablePrime(q) && isPocklingtonCriterionSatisfied(p) && q.bitLength() === qBitLen) {
			const sgp = new GermainSafePrime(q, p);
			if (sgp.validate()) {
				return sgp;
			}
		}
	}
}

function isPrimeCandidate(num: BN): boolean {
	const m = num.mod(smallPrimesProduct);
	for (const prime of smallPrimes) {
		const p = new BN(prime);
		if (m.mod(p).isZero() && !m.eq(p)) {
			return false;
		}
	}
	return true;
}

function isPocklingtonCriterionSatisfied(p: BN): boolean {
	return two.pow(p.subn(1)).mod(p).eq(one);
}