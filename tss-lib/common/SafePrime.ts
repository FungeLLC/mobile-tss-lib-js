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
		for (const p of smallPrimes) {
			if (n.modn(p) === 0) return n.eqn(p);
		}
	}

	// Miller-Rabin test with first few prime numbers as bases
	const witnesses = [
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97, 101, 103, 107, 109, 113
	];

	for (let i = 0; i < Math.min(witnesses.length, primeTestN); i++) {
		if (!millerRabinTest(n, new BN(witnesses[i]))) {
			return false;
		}
	}

	return true;
}

function isSafePrime(p: BN): boolean {
	if (!isProbablePrime(p)) return false;

	// For safe prime p, (p-1)/2 must also be prime
	const q = p.subn(1).divn(2);
	return isProbablePrime(q);
}

function generateSafePrime(bits: number): BN {
	while (true) {
		// Generate random q
		const bytes = crypto.randomBytes(Math.ceil((bits - 1) / 8));
		const q = new BN(bytes);

		// Ensure q is odd and in correct range
		q.setn(bits - 2, 1);  // Set highest bit
		q.setn(0, 1);         // Ensure odd

		// Check if q is prime
		if (!isProbablePrime(q)) continue;

		// Calculate p = 2q + 1
		const p = q.muln(2).addn(1);

		// Check if p is prime
		if (isProbablePrime(p)) {
			return p;
		}
	}
}

export {generateSafePrime, isSafePrime, isProbablePrime, millerRabinTest};