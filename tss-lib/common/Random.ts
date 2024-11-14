import { randomBytes } from 'crypto';


const mustGetRandomIntMaxBits = 5000;

export function mustGetRandomInt(bits: number): bigint {
	if (bits <= 0 || mustGetRandomIntMaxBits < bits) {
		throw new Error(`mustGetRandomInt: bits should be positive, non-zero and less than ${mustGetRandomIntMaxBits}`);
	}
	const max = (BigInt(1) << BigInt(bits)) - BigInt(1);
	const randomInt = BigInt('0x' + randomBytes(Math.ceil(bits / 8)).toString('hex'));
	return randomInt % (max + BigInt(1));
}

export function getRandomPositiveInt(lessThan: bigint): bigint | null {
	if (lessThan <= BigInt(0)) {
		return null;
	}
	let tryInt: bigint;
	do {
		tryInt = mustGetRandomInt(lessThan.toString(2).length);
	} while (tryInt >= lessThan);
	return tryInt;
}

export function getRandomPrimeInt(bits: number): bigint | null {
	if (bits <= 0) {
		return null;
	}
	let prime: bigint;
	do {
		prime = mustGetRandomInt(bits);
	} while (!isProbablyPrime(prime));
	return prime;
}

export function getRandomPositiveRelativelyPrimeInt(n: bigint): bigint | null {
	if (n <= BigInt(0)) {
		return null;
	}
	let tryInt: bigint;
	do {
		tryInt = mustGetRandomInt(n.toString(2).length);
	} while (!isNumberInMultiplicativeGroup(n, tryInt));
	return tryInt;
}

export function isNumberInMultiplicativeGroup(n: bigint, v: bigint): boolean {
	if (n <= BigInt(0) || v <= BigInt(0)) {
		return false;
	}
	return gcd(n, v) === BigInt(1);
}

export function getRandomGeneratorOfTheQuadraticResidue(n: bigint): bigint {
	const f = getRandomPositiveRelativelyPrimeInt(n);
	if (!f) {
		throw new Error('Failed to generate random positive relatively prime integer');
	}
	const fSq = (f * f) % n;
	return fSq;
}

export function getRandomQuadraticNonResidue(n: bigint): bigint {
	let w: bigint;
	do {
		const randomInt = getRandomPositiveInt(n);
		if (randomInt === null) {
			throw new Error('Failed to generate random positive integer');
		}
		w = randomInt;
	} while (bigIntJacobi(w, n) !== -1);
	return w;
}

export function getRandomBytes(length: number): Buffer {
	if (length <= 0) {
		throw new Error('invalid length');
	}
	return randomBytes(length);
}

function isProbablyPrime(n: bigint): boolean {
	// Implement a simple primality test or use a library
	// This is a placeholder implementation
	return true;
}

function gcd(a: bigint, b: bigint): bigint {
	while (b !== BigInt(0)) {
		const temp = b;
		b = a % b;
		a = temp;
	}
	return a;
}

function bigIntJacobi(a: bigint, n: bigint): number {
	// Implement the Jacobi symbol calculation
	// This is a placeholder implementation
	return 1;
}