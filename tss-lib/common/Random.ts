import { randomBytes } from 'crypto';
import BN from 'bn.js';
import { SHA512_256i } from '../common/Hash';

type BigNumber = bigint | BN;

const mustGetRandomIntMaxBits = 5000;


export function RejectionSample(q: BN, eHash: BN): BN {
	// RejectionSample implements the rejection sampling logic for converting a
	// SHA512/256 hash to a value between 0-q
	return eHash.mod(q);
}

export function RejectionSampleFromBuffer(q: BN, buffer: Buffer): BN {
	const eHash = new BN(buffer);
	return RejectionSample(q, eHash);
}

export function RejectionSampleHash(q: BN, ...inputs: BN[]): BN {
	const eHash = SHA512_256i(...inputs);
	return RejectionSample(q, eHash);
}


function toBigInt(n: BigNumber): bigint {
	return typeof n === 'bigint' ? n : BigInt(n.toString());
}

function toBN(n: BigNumber): BN {
	return BN.isBN(n) ? n : new BN(n.toString());
}

export function mustGetRandomInt(bits: number): BigNumber {
	if (bits <= 0 || mustGetRandomIntMaxBits < bits) {
		throw new Error(`mustGetRandomInt: bits should be positive, non-zero and less than ${mustGetRandomIntMaxBits}`);
	}
	const max = (BigInt(1) << BigInt(bits)) - BigInt(1);
	const randomInt = BigInt('0x' + randomBytes(Math.ceil(bits / 8)).toString('hex'));
	return new BN((randomInt % (max + BigInt(1))).toString());
}

export function getRandomPositiveInt(lessThan: BigNumber): BigNumber | null {
	const lessThanBigInt = toBigInt(lessThan);
	if (lessThanBigInt <= BigInt(0)) {
		return null;
	}
	let tryInt: BigNumber;
	do {
		tryInt = mustGetRandomInt(lessThanBigInt.toString(2).length);
	} while (toBigInt(tryInt) >= lessThanBigInt);
	return tryInt;
}

export function getRandomPrimeInt(bits: number): BigNumber | null {
	if (bits <= 0) {
		return null;
	}
	let prime: BigNumber;
	do {
		prime = mustGetRandomInt(bits);
	} while (!isProbablyPrime(toBigInt(prime)));
	return prime;
}

export function getRandomPositiveRelativelyPrimeInt(n: BigNumber): BigNumber | null {
	const nBigInt = toBigInt(n);
	if (nBigInt <= BigInt(0)) {
		return null;
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

function isProbablyPrime(n: bigint): boolean {
	// Implement Miller-Rabin primality test
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
	// Implement Jacobi symbol calculation
	return 1;
}