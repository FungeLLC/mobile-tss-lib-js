
import { BN } from 'bn.js';
import { RejectionSample } from '../../common/hash_utils';
import { getRandomBytes } from '../../common/Random';

describe('RejectionSample', () => {
	
	it('should handle multiple RejectionSample calls consistently', () => {
			const q = new BN('1000000007'); // Prime number
			for (let i = 0; i < 10; i++) {
				const hash = new BN(getRandomBytes(32));
				const result = RejectionSample(q, hash);

				console.log("REjection sample",result.toString());
				
				expect(result.lt(q)).toBe(true);
				expect(result.gten(0)).toBe(true);
			}
		});

	it('should return value between 0 and q', () => {
		const q = new BN('100');
		const hash = new BN('200');
		const result = RejectionSample(q, hash);
		expect(result.lt(q)).toBe(true);
		expect(result.gte(new BN(0))).toBe(true);
	}
	);
	it('should handle edge cases with q', () => {
		const q = new BN('2');
		const hash = new BN('1000');
		const result = RejectionSample(q, hash);
		expect(result.lt(q)).toBe(true);
		expect(result.gte(new BN(0))).toBe(true);
	});

	it('should handle large numbers', () => {
		const q = new BN('340282366920938463463374607431768211456'); // 2^128
		const hash = new BN('340282366920938463463374607431768211457'); // q + 1
		const result = RejectionSample(q, hash);
		expect(result.lt(q)).toBe(true);
		expect(result.gte(new BN(0))).toBe(true);
	});

	it('should handle hash equal to q', () => {
		const q = new BN('100');
		const hash = new BN('100');
		const result = RejectionSample(q, hash);
		expect(result.lt(q)).toBe(true);
		expect(result.gte(new BN(0))).toBe(true);
	});

	it('should handle hash smaller than q', () => {
		const q = new BN('1000');
		const hash = new BN('50');
		const result = RejectionSample(q, hash);
		expect(result.lt(q)).toBe(true);
		expect(result.gte(new BN(0))).toBe(true);
	});
	
}
);
