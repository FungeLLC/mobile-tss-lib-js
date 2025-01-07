import { SHA512_256, SHA512_256i, SHA512_256i_TAGGED, SHA512_256iOne } from '../../common/Hash';
import { RejectionSample } from '../../common/hash_utils';
import BN from 'bn.js';
import crypto from 'crypto';

describe('Hash Functions', () => {
	test('SHA512_256 hashes buffers correctly', () => {
		const input1 = Buffer.from('hello');
		const input2 = Buffer.from('world');
		const hash = SHA512_256(input1, input2);
		expect(hash).toBeInstanceOf(Buffer);
		expect(hash.length).toBe(32);
	});

	test('SHA512_256i hashes BNs correctly', () => {
		const bn1 = new BN('1234567890abcdef', 16);
		const bn2 = new BN('fedcba0987654321', 16);
		const hash = SHA512_256i(bn1, bn2);
		expect(hash).toBeInstanceOf(BN);
		if(hash instanceof BN) {
			expect(hash.toArrayLike(Buffer).length).toBe(32);
		}
	});

	test('SHA512_256i_TAGGED hashes tagged BNs correctly', () => {
		const tag = Buffer.from('test tag');
		const bn1 = new BN('1122334455667788', 16);
		const hash = SHA512_256i_TAGGED(tag, bn1);
		expect(hash).toBeInstanceOf(BN);
		expect(hash.toArrayLike(Buffer).length).toBe(32);
	});

	test('SHA512_256iOne hashes a single BN correctly', () => {
		const bn = new BN('abcdef1234567890', 16);
		const hash = SHA512_256iOne(bn);
		expect(hash).toBeInstanceOf(BN);
		expect(hash.toArrayLike(Buffer).length).toBe(32);
	});

	test('RejectionSample computes modulo correctly', () => {
		const q = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16);
		const eHash = crypto.randomBytes(32);
		const eHashBN = new BN(eHash);
		const result = RejectionSample(q, eHashBN);
		expect(result).toBeInstanceOf(BN);
		expect(result.lt(q)).toBe(true);
	});
});


import * as fs from 'fs';
import * as path from 'path';

describe('SHA512_256i Cross-Implementation Tests', () => {
	const testVectorPath = path.join(__dirname, 'hash_test_vectors.json');
	const testVectors = JSON.parse(fs.readFileSync(testVectorPath, 'utf8'));

	testVectors.tests.forEach((testCase: any) => {
		test(`matches Go implementation: ${testCase.name}`, () => {
			// Convert hex inputs to BNs
			const inputs = testCase.inputs.map((hex: string) => new BN(hex, 16));

			// Generate hash
			const result = SHA512_256i(...inputs);

			// Handle empty input case
			if (testCase.output === "<nil>") {
				expect(result).toStrictEqual(new BN(0))
				return;
			}

			// Compare with expected output
			expect(result).not.toBeNull();
			if (result) {
				const resultHex = result.toString(16);
				const expectedHex = testCase.output;
				expect(resultHex).toBe(expectedHex);

				// Log details if test fails
				if (resultHex !== expectedHex) {
					console.log('Test case:', testCase.name);
					console.log('Inputs:', testCase.inputs);
					console.log('Expected:', expectedHex);
					console.log('Got:', resultHex);
				}
			}
		});
	});
});