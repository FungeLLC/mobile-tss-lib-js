import { SHA512_256i } from '../common/Hash';
import ModInt from './ModInt';
import BN from 'bn.js';

const modIntCache = new Map<string, ModInt>();


// RejectionSample implements the rejection sampling logic for converting a
// SHA512/256 hash to a value between 0-q
export function RejectionSample(q: BN, eHash: BN): BN {
    // Get or create ModInt instance for this modulus
    const qStr = q.toString(16);
    let qModInt = modIntCache.get(qStr);
    if (!qModInt) {
        qModInt = new ModInt(q);
        modIntCache.set(qStr, qModInt);
    }

    // Use reduction if hash is positive (faster)
    if (!eHash.isNeg()) {
        const reduced = qModInt.reduce(eHash);
        // Ensure the reduced value is within the range [0, q)
        return reduced;
    }

    // Fallback to regular mod for negative numbers
    return eHash.mod(q);
}

export function RejectionSampleFromBuffer(q: BN, buffer: Buffer): BN {
	const eHash = new BN(buffer);
	return RejectionSample(q, eHash);
}

export function RejectionSampleHash(q: BN, ...inputs: BN[]): BN {
	const eHash = SHA512_256i(...inputs);
	if (!eHash) {
		throw new Error('Failed to generate hash');
	}
	return RejectionSample(q, eHash);
}
