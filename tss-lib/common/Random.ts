import { randomBytes } from 'node:crypto';
import BN from 'bn.js';


type BigNumber = bigint | BN;

const mustGetRandomIntMaxBits = 5000;




function toBigInt(n: BigNumber): bigint {
	return typeof n === 'bigint' ? n : BigInt(n.toString());
}

function toBN(n: BigNumber): BN {
	return BN.isBN(n) ? n : new BN(n.toString());
}

export function mustGetRandomInt(bits: number): BN {
	if (bits <= 0 || mustGetRandomIntMaxBits < bits) {
		throw new Error(`mustGetRandomInt: bits should be positive, non-zero and less than ${mustGetRandomIntMaxBits}`);
	}
	const max = (BigInt(1) << BigInt(bits)) - BigInt(1);
	const randomInt = BigInt('0x' + randomBytes(Math.ceil(bits / 8)).toString('hex'));
	return new BN((randomInt % (max + BigInt(1))).toString());
}

export function getRandomPositiveInt(lessThan: BigNumber): BN  {
	const lessThanBigInt = toBigInt(lessThan);
	if (lessThanBigInt <= BigInt(0)) {
		throw new Error('lessThan must be a positive integer');
	}
	let tryInt: BN;
	do {
		tryInt = mustGetRandomInt(lessThanBigInt.toString(2).length);
	} while (toBigInt(tryInt) >= lessThanBigInt);
	return tryInt;
}

export function getRandomPrimeInt(bits: number): BN {
	if (bits <= 0) {
		throw new Error('bits should be positive');
	}
	let prime: BN;
	do {
		const maxAttempts = 1000;  // Prevent infinite loops
		let attempts = 0;
		do {
			// Generate number with exact bit length and ensure it's odd
			prime = mustGetRandomInt(bits);
			prime = prime.ior(new BN(1));  // Make odd by setting least significant bit
			if (prime.bitLength() !== bits) {
			prime = prime.bincn(bits - 1);  // Set highest bit to ensure correct length
			}
			attempts++;
			if (attempts >= maxAttempts) {
			throw new Error('Failed to find prime number after ' + maxAttempts + ' attempts');
			}
		} while (!isProbablyPrime(toBigInt(prime)));
		attempts = 0;  // Reset for next use
		console.log("prime",prime.toString());
	} while (!isProbablyPrime(toBigInt(prime)));
	return prime;
}

export function getRandomPositiveRelativelyPrimeInt(n: BigNumber): BN {
	const nBigInt = toBigInt(n);
	if (nBigInt <= BigInt(0)) {
		throw new Error('n must be a positive integer');
	}
	let tryInt: BigNumber;
	do {
		tryInt = mustGetRandomInt(nBigInt.toString(2).length);
	} while (!isNumberInMultiplicativeGroup(nBigInt, toBigInt(tryInt)));
	return tryInt;
}

export function isNumberInMultiplicativeGroup(n: BigNumber, v: BigNumber): boolean {
	const nBigInt = toBigInt(n);
	const vBigInt = toBigInt(v);
	if (nBigInt <= BigInt(0) || vBigInt <= BigInt(0)) {
		return false;
	}
	return gcd(nBigInt, vBigInt) === BigInt(1);
}

export function getRandomGeneratorOfTheQuadraticResidue(n: BigNumber): BigNumber {
	const nBigInt = toBigInt(n);
	const f = getRandomPositiveRelativelyPrimeInt(nBigInt);
	if (!f) {
		throw new Error('Failed to generate random positive relatively prime integer');
	}
	const fSq = (toBigInt(f) * toBigInt(f)) % nBigInt;
	return new BN(fSq.toString());
}

export function getRandomQuadraticNonResidue(n: BigNumber): BN {
	const nBigInt = toBigInt(n);
	let w: BigNumber;
	do {
		const randomInt = getRandomPositiveInt(nBigInt);
		if (randomInt === null) {
			throw new Error('Failed to generate random positive integer');
		}
		w = randomInt;
	} while (bigIntJacobi(toBigInt(w), nBigInt) !== -1);
	return new BN(w.toString());
}

export function getRandomBytes(length: number): Buffer {
	if (length <= 0) {
		throw new Error('invalid length');
	}
	return randomBytes(length);
}

export function isProbablyPrime(n: BigNumber): boolean {
	const nBN = toBN(n);

	// Quick checks first
	if (nBN.lte(new BN(1)) || nBN.mod(new BN(2)).isZero()) return false;
	if (nBN.lte(new BN(3))) return true;

	// Use fewer witnesses based on input size
	const bits = nBN.bitLength();
	let witnesses: number[];
	
	if (bits <= 64) {
		witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]; // For numbers < 2^64
	} else if (bits <= 128) {
		witnesses = [2, 3, 7, 61, 24251]; // For numbers < 2^128
	} else {
		witnesses = [2, 3, 5, 7, 11, 13, 17]; // For larger numbers
	}

	// Find d and r where n - 1 = d * 2^r
	let d = nBN.subn(1);
	let r = 0;
	while (d.isEven()) {
		d = d.shrn(1);
		r++;
	}

	const red = BN.mont(nBN);
	witnessLoop: for (const a of witnesses) {
		if (new BN(a).gte(nBN)) continue;
		
		let x = new BN(a).toRed(red).redPow(d);
		if (x.fromRed().eqn(1) || x.fromRed().eq(nBN.subn(1))) continue;

		for (let i = 1; i < r; i++) {
			x = x.redSqr();
			const xr = x.fromRed();
			if (xr.eq(nBN.subn(1))) continue witnessLoop;
			if (xr.eqn(1)) return false;
		}
		return false;
	}
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
	if (n <= 0 || n % BigInt(2) === BigInt(0)) {
		throw new Error('n must be a positive odd number');
	}
	let acc = 1;
	a = ((a % n) + n) % n;

	while (a !== BigInt(0)) {
		while (a % BigInt(2) === BigInt(0)) {
			a /= BigInt(2);
			const r = n % BigInt(8);
			if (r === BigInt(3) || r === BigInt(5)) acc = -acc;
		}
		[a, n] = [n, a];
		if (a % BigInt(4) === BigInt(3) && n % BigInt(4) === BigInt(3)) acc = -acc;
		a = a % n;
	}
	return n === BigInt(1) ? acc : 0;
}

type RandomSource = {
	randomBytes(size: Number): Buffer;
};

export function getRandomSource(): RandomSource {
	return {
		randomBytes: randomBytes
	};
}