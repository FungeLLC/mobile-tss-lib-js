// dlnproof.test.ts
import { DLNProof } from '../../crypto/DLNProof';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';
import { RandomBytesProvider } from '../../common/Types';
import * as fs from 'fs';
import * as path from 'path';
import { testLogger } from '../../common/Logger';


describe('DLN Proof Tests', () => {
	let ec: EC;
	const mockRand: RandomBytesProvider = {
		randomBytes: (size: number) => crypto.randomBytes(size)
	};

	beforeAll(() => {
		process.stdout.write('Starting DLN Proof tests\n');
		ec = new EC('secp256k1');
		process.stdout.write(`Using curve: ${ec.curve.type}\n`);
	});

	describe('Cross-Implementation Tests', () => {
		it('should verify Go-generated proof', () => {
			// Read test vector
			const testVectorPath = path.join(__dirname, 'test_vector.json');
			const testVector = JSON.parse(fs.readFileSync(testVectorPath, 'utf8'));

			console.log('Test vector:', testVector);

			// Convert input values from hex strings to BN
			const h1 = new BN(testVector.input.h1, 16);
			const h2 = new BN(testVector.input.h2, 16);
			const p = new BN(testVector.input.p, 16);
			const q = new BN(testVector.input.q, 16);
			const N = new BN(testVector.input.nTilde, 16);

			// Convert proof values from hex strings to BN arrays
			const alpha = testVector.proof.alpha.map((a: string) => new BN(a, 16));
			const t = testVector.proof.t.map((t: string) => new BN(t, 16));

			// Create and verify proof
			const proof = new DLNProof(alpha, t);

			console.log('Verifying Go-generated proof...');
			console.log('Input values:');
			console.log('h1:', h1.toString(16));
			console.log('h2:', h2.toString(16));
			console.log('N:', N.toString(16));

			const result = proof.verify(h1, h2, N);
			console.log('Verification result:', result);
			expect(result).toBe(true);
		});


		it('should generate proof verifiable by Go', () => {
			// Use same test values
			// Read test vector
			const testVectorPath = path.join(__dirname, 'test_vector.json');
			const testVector = JSON.parse(fs.readFileSync(testVectorPath, 'utf8'));

			// Convert input values from hex strings to BN
			const h1 = new BN(testVector.input.h1, 16);
			const h2 = new BN(testVector.input.h2, 16);
			const x = new BN(testVector.input.alpha, 16);
			const p = new BN(testVector.input.p, 16);
			const q = new BN(testVector.input.q, 16);
			const N = new BN(testVector.input.nTilde, 16);
			const c = new BN(testVector.challenge, 16);

			console.log('Test parameters:', {
				h1: h1.toString(16),
				h2: h2.toString(16),
				x: x.toString(16),
				N: N.toString(16)
			});

			const seed = Buffer.from([
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
			]);
			const mockRand: RandomBytesProvider = {
				randomBytes: (size: number) => {
					// Expand seed to requested size
					const result = Buffer.alloc(size);
					for (let i = 0; i < size; i++) {
						result[i] = seed[i % seed.length];
					}
					return result;
				}
			};


			// Generate proof
			// const DlnProof = new DLNProof(Alpha, T);

			const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, testLogger);

			// Create test vector
			const vector = {
				input: {
					h1: h1.toString(16),
					h2: h2.toString(16),
					alpha: x.toString(16),
					p: p.toString(16),
					q: q.toString(16),
					nTilde: N.toString(16)
				},
				proof: {
					alpha: proof.getAlpha().map(a => a.toString(16)),
					t: proof.getT().map(t => t.toString(16))
				}
			};

			// Save test vector
			const jsonStr = JSON.stringify(vector, null, 2);
			const testOutVectorPath = path.join(__dirname, 'generated_test_vector.json');
			fs.writeFileSync(testOutVectorPath, jsonStr);

			// Verify generated proof works
			expect(proof.verify(h1, h2, N)).toBe(true);
		});
	});

	describe('Proof Generation and Verification', () => {
		// Add timeout to prevent hanging
		jest.setTimeout(10000); // 10 second timeout

		it('should create and verify valid proof', () => {
			console.log('Starting proof test');

			// Read test vector
			const testVectorPath = path.join(__dirname, 'generated_test_vector.json');
			const testVector = JSON.parse(fs.readFileSync(testVectorPath, 'utf8'));

			// Convert input values from hex strings to BN
			const h1 = new BN(testVector.input.h1, 16);
			const h2 = new BN(testVector.input.h2, 16);
			const x = new BN(testVector.input.alpha, 16);
			const p = new BN(testVector.input.p, 16);
			const q = new BN(testVector.input.q, 16);
			const N = new BN(testVector.input.nTilde, 16);

			console.log('Test parameters:', {
				h1: h1.toString(16),
				h2: h2.toString(16),
				x: x.toString(16),
				N: N.toString(16)
			});

			// Convert proof values from hex strings to BN arrays
			const alpha = testVector.proof.alpha.map((a: string) => new BN(a, 16));
			const t = testVector.proof.t.map((t: string) => new BN(t, 16));

			const proof = new DLNProof(alpha, t);
			const result = proof.verify(h1, h2, N);

			console.log('Verification result:', result);
			expect(result).toBe(true);
		});

		it('should reject invalid proof values', () => {
			const testVectorPath = path.join(__dirname, 'generated_test_vector.json');
			const testVector = JSON.parse(fs.readFileSync(testVectorPath, 'utf8'));

			const h1 = new BN(testVector.input.h1, 16);
			const h2 = new BN(testVector.input.h2, 16);
			const N = new BN(testVector.input.nTilde, 16);
			const wrongN = N.add(new BN(1)); // Use wrong N value

			const alpha = testVector.proof.alpha.map((a: string) => new BN(a, 16));
			const t = testVector.proof.t.map((t: string) => new BN(t, 16));

			const proof = new DLNProof(alpha, t);
			expect(proof.verify(h1, h2, wrongN)).toBe(false);
		});

		it('should serialize and deserialize proof', () => {
			const testVectorPath = path.join(__dirname, 'generated_test_vector.json');
			const testVector = JSON.parse(fs.readFileSync(testVectorPath, 'utf8'));

			const h1 = new BN(testVector.input.h1, 16);
			const h2 = new BN(testVector.input.h2, 16);
			const N = new BN(testVector.input.nTilde, 16);

			const alpha = testVector.proof.alpha.map((a: string) => new BN(a, 16));
			const t = testVector.proof.t.map((t: string) => new BN(t, 16));

			const proof = new DLNProof(alpha, t);
			const serialized = proof.serialize();
			expect(serialized).toBeTruthy();
			// expect(Buffer.isBuffer(serialized)).toBe(true);

			const deserialized = DLNProof.unmarshalDLNProof(serialized);
			expect(deserialized).toBeInstanceOf(DLNProof);
			const verifyResult = deserialized.verify(h1, h2, N);
			console.log('Verify result:', verifyResult);
			expect(verifyResult).toBe(true);
		});
	});

	describe('DLNProof Verify Tests', () => {
		let ec: EC;

		beforeAll(() => {
			ec = new EC('secp256k1');
		});

		it('should reject when h1 equals h2', () => {
			const h = new BN(ec.g.getX());
			const x = new BN('123456789');
			const p = new BN('FFFF', 16);
			const q = new BN('FFFD', 16);
			const N = p.mul(q);

			const proof = DLNProof.newDLNProof(h, h, x, p, q, N, testLogger);
			expect(proof.verify(h, h, N)).toBe(false);
		});

		it('should reject negative modulus', () => {
			const h1 = new BN(ec.g.getX());
			const h2 = new BN(ec.g.getY());
			const x = new BN('123456789');
			const p = new BN('FFFF', 16);
			const q = new BN('FFFD', 16);
			const N = p.mul(q).neg();

			expect(() => DLNProof.newDLNProof(h1, h2, x, p, q, N, testLogger)).toThrow('Invalid N: N <= 1');
		});

		it('should reject when h1 is out of range', () => {
			const h1 = new BN('FFFFFFFFFFFFFFFF', 16); // Large value
			const h2 = new BN(ec.g.getY());
			const x = new BN('123456789');
			const p = new BN('FFFF', 16);
			const q = new BN('FFFD', 16);
			const N = p.mul(q);

			const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, testLogger);
			expect(proof.verify(h1, h2, N)).toBe(false);
		});


	}
	)
}
);