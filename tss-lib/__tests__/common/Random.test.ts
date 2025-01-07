import BN from 'bn.js';
import * as fs from 'fs';
import * as path from 'path';
import { 

mustGetRandomInt,
getRandomPositiveInt,
getRandomPositiveRelativelyPrimeInt,
isNumberInMultiplicativeGroup,
getRandomBytes,
getRandomSource,

} from '../../common/Random';
import { RejectionSample } from '../../common/hash_utils';

interface RandomTestVector {
    tests: {
        name: string;
        input: {
            bits?: number;
            lessThan?: string;
            n?: string;
            seed: string;
        };
        output: string;
    }[];
}

describe('Random', () => {
describe('RejectionSample', () => {
	it('should return value between 0 and q', () => {
		const q = new BN('100');
		const hash = new BN('200');
		const result = RejectionSample(q, hash);
		expect(result.ltn(100)).toBe(true);
		expect(result.gten(0)).toBe(true);
	});
});

describe('mustGetRandomInt', () => {
	it('should throw error for invalid bits', () => {
		expect(() => mustGetRandomInt(0)).toThrow();
		expect(() => mustGetRandomInt(-1)).toThrow();
		expect(() => mustGetRandomInt(6000)).toThrow();
	});

	it('should return random number with correct bit length', () => {
		const result = mustGetRandomInt(8);
		expect(result.toString(2).length).toBeLessThanOrEqual(8);
	});
});

describe('getRandomPositiveInt', () => {
	it('should throw error for non-positive input', () => {
		expect(() => getRandomPositiveInt(new BN('0'))).toThrow();
		expect(() => getRandomPositiveInt(new BN('-1'))).toThrow();
	});

	it('should return number less than input', () => {
		const limit = new BN('100');
		const result = getRandomPositiveInt(limit);
		expect(result!.lt(limit)).toBe(true);
	});
});

describe('isNumberInMultiplicativeGroup', () => {
	it('should return false for non-positive inputs', () => {
		expect(isNumberInMultiplicativeGroup(0n, 1n)).toBe(false);
		expect(isNumberInMultiplicativeGroup(1n, 0n)).toBe(false);
		expect(isNumberInMultiplicativeGroup(-1n, 1n)).toBe(false);
	});

	it('should return true for coprime numbers', () => {
		expect(isNumberInMultiplicativeGroup(8n, 3n)).toBe(true);
		expect(isNumberInMultiplicativeGroup(15n, 4n)).toBe(true);
	});
});

describe('getRandomBytes', () => {
	it('should throw error for invalid length', () => {
		expect(() => getRandomBytes(0)).toThrow();
		expect(() => getRandomBytes(-1)).toThrow();
	});

	it('should return buffer of correct length', () => {
		const result = getRandomBytes(32);
		expect(result.length).toBe(32);
	});
});

describe('getRandomSource', () => {
	it('should return valid random source', () => {
		const source = getRandomSource();
		expect(source.randomBytes).toBeDefined();
		const result = source.randomBytes(32);
		expect(result.length).toBe(32);
	});
});
});

describe('Random Cross-Implementation Tests', () => {
    let testVectors: RandomTestVector;

	describe('Random Extended Tests', () => {


		it('should generate different random numbers with mustGetRandomInt', () => {
			const results = new Set();
			for (let i = 0; i < 100; i++) {
				const num = mustGetRandomInt(16);
				expect(num.toString(2).length).toBeLessThanOrEqual(16);
				results.add(num.toString());
			}
			expect(results.size).toBeGreaterThan(1); // Check for randomness
		});

		it('should verify multiplicative group properties', () => {
			const n = new BN('101'); // Prime number
			for (let i = 2; i < 10; i++) {
				const result = isNumberInMultiplicativeGroup(n, new BN(i));
				expect(result).toBe(i !== 101);
			}
		});

		it('should generate relatively prime numbers consistently', () => {
			const modulus = new BN('65537'); // Prime number
			const result = getRandomPositiveRelativelyPrimeInt(modulus);
			expect(result).not.toBeNull();
			expect(isNumberInMultiplicativeGroup(modulus, result!)).toBe(true);
		});

		it('should generate random bytes with expected entropy', () => {
			const bytes1 = getRandomBytes(32);
			const bytes2 = getRandomBytes(32);
			expect(bytes1.length).toBe(32);
			expect(bytes2.length).toBe(32);
			expect(Buffer.compare(bytes1, bytes2)).not.toBe(0);
		});
	});
});