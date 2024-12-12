import ModInt from '../../common/ModInt';
import BN from 'bn.js';

describe('ModInt expWindow', () => {
	let modInt: ModInt;

	beforeEach(() => {
		// Use a small prime modulus for testing
		modInt = new ModInt(new BN(23));
	});

	it('should correctly compute modular exponentiation with window size 1', () => {
		const base = new BN(2);
		const exp = new BN(5);
		const windowSize = 1;
		
		// 2^5 mod 23 = 32 mod 23 = 9
		const expected = new BN(9);
		const result = modInt.expWindow(base, exp, windowSize);
		
		expect(result.eq(expected)).toBe(true);
	});

	it('should correctly compute modular exponentiation with window size 2', () => {
		const base = new BN(3);
		const exp = new BN(7);
		const windowSize = 2;
		
		// 3^7 mod 23 = 2187 mod 23 = 13
		const expected = new BN(13);
		const result = modInt.expWindow(base, exp, windowSize);
		
		expect(result.eq(expected)).toBe(true);
	});

	it('should handle base case of exponent 0', () => {
		const base = new BN(5);
		const exp = new BN(0);
		const windowSize = 2;
		
		// 5^0 mod 23 = 1
		const expected = new BN(1);
		const result = modInt.expWindow(base, exp, windowSize);
		
		expect(result.eq(expected)).toBe(true);
	});

	it('should handle base case of exponent 1', () => {
		const base = new BN(7);
		const exp = new BN(1);
		const windowSize = 3;
		
		// 7^1 mod 23 = 7
		const expected = new BN(7);
		const result = modInt.expWindow(base, exp, windowSize);
		
		expect(result.eq(expected)).toBe(true);
	});

	it('should compute with precomputed window', () => {
		const base = new BN(2);
		const exp = new BN(6);
		const windowSize = 2;
		
		const precomputedWindow = modInt.precomputeWindow(base, windowSize);
		const result = modInt.expWindow(base, exp, windowSize, precomputedWindow);
		
		// 2^6 mod 23 = 64 mod 23 = 18
		const expected = new BN(18);
		expect(result.eq(expected)).toBe(true);
	});

	it('should handle larger numbers correctly', () => {
		const largeModInt = new ModInt(new BN('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16));
		const base = new BN('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 16);
		const exp = new BN('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 16);
		const windowSize = 4;
		
		const result = largeModInt.expWindow(base, exp, windowSize);
		expect(result.toString(16).length).toBeLessThanOrEqual(64); // Should be within modulus size
	});

	it('should throw error for negative exponents', () => {
		const base = new BN(2);
		const exp = new BN(-1);
		const windowSize = 2;
		
		expect(() => {
			modInt.expWindow(base, exp, windowSize);
		}).toThrow();
	});
});