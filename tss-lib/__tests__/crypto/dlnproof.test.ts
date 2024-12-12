// dlnproof.test.ts
import { DLNProof } from '../../crypto/DLNProof';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';
import { RandomBytesProvider } from '../../common/Types';

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

	describe('Proof Generation and Verification', () => {
		// Add timeout to prevent hanging
		jest.setTimeout(10000); // 10 second timeout

		it('should create and verify valid proof', () => {
			console.log('Starting proof test');

			const h1 = new BN(ec.g.getX());
			const h2 = new BN(ec.g.getY());
			console.log('Using curve points:', {
				h1: h1.toString(16),
				h2: h2.toString(16)
			});

			// Use much smaller test values initially
			const x = new BN('123456789');
			const p = new BN('FFFF', 16); // Smaller prime for testing
			const q = new BN('FFFD', 16); // Smaller prime for testing
			const N = p.mul(q);

			console.log('Test parameters:', {
				x: x.toString(16),
				p: p.toString(16),
				q: q.toString(16),
				N: N.toString(16)
			});

			const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, mockRand);
			const result = proof.verify(h1, h2, N);

			console.log('Original proof:', {
				xValues: proof.getXValues().map(x => x.toString(16)),
				eValues: proof.getEValues().map(e => e.toString(16))
			});

			console.log('Verification result:', result);

			expect(result).toBe(true);
		});

		it('should reject invalid proof values', () => {
			const h1 = new BN(ec.g.getX());
			const h2 = new BN(ec.g.getY());
			const x = new BN('123456789');
			const p = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
			const q = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142', 16);
			const N = p.mul(q);
			const wrongN = p.mul(p);

			const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, mockRand);
			expect(proof.verify(h1, h2, wrongN)).toBe(false);
		});

		it('should serialize and deserialize proof', () => {
			const h1 = new BN(ec.g.getX());
			const h2 = new BN(ec.g.getY());
			const x = new BN('123456789');
			const p = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
			const q = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142', 16);
			const N = p.mul(q);

			const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, mockRand);
			const serialized = proof.serialize();
			expect(serialized).toBeTruthy();
			expect(typeof serialized).toBe('object');

			const deserialized = DLNProof.unmarshalDLNProof(serialized);
			expect(deserialized).toBeInstanceOf(DLNProof);
			console.log('Original proof:', {
				xValues: proof.getXValues().map(x => x.toString(16)),
				eValues: proof.getEValues().map(e => e.toString(16))
			});
			console.log('Deserialized proof:', {
				xValues: deserialized.getXValues().map(x => x.toString(16)),
				eValues: deserialized.getEValues().map(e => e.toString(16))
			});
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

			const proof = DLNProof.newDLNProof(h, h, x, p, q, N);
			expect(proof.verify(h, h, N)).toBe(false);
		});

		it('should reject negative modulus', () => {
			const h1 = new BN(ec.g.getX());
			const h2 = new BN(ec.g.getY());
			const x = new BN('123456789');
			const p = new BN('FFFF', 16);
			const q = new BN('FFFD', 16);
			const N = p.mul(q).neg();

			const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N);
			expect(proof.verify(h1, h2, N)).toBe(false);
		});

		it('should reject when h1 is out of range', () => {
			const h1 = new BN('FFFFFFFFFFFFFFFF', 16); // Large value
			const h2 = new BN(ec.g.getY());
			const x = new BN('123456789');
			const p = new BN('FFFF', 16);
			const q = new BN('FFFD', 16);
			const N = p.mul(q);

			const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N);
			expect(proof.verify(h1, h2, N)).toBe(false);
		});

		describe('Cryptographic Value Tests', () => {
				let ec: EC;
				const mockRand: RandomBytesProvider = {
					randomBytes: (size: number) => crypto.randomBytes(size)
				};

				beforeAll(() => {
					ec = new EC('secp256k1');
				});

				it('should verify with smaller cryptographic values', () => {
					const h1 = new BN(ec.g.getX());
					const h2 = new BN(ec.g.getY());
					// Use smaller but still cryptographically valid values
					const x = new BN('123456789abcdef0', 16);
					const p = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
					const q = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D', 16);
					const N = p.mul(q);

					const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, mockRand);
					expect(proof.verify(h1, h2, N)).toBe(true);
				});

				it('should verify with secp256k1 curve order parameters', () => {
					const h1 = new BN(ec.g.getX());
					const h2 = new BN(ec.g.getY());
					const x = new BN('123456789abcdef0', 16);
					// Using secp256k1 curve order as reference
					const p = ec.n;
					if (!p) throw new Error('Curve order is undefined');
					const q = p.subn(1);
			const N = p.mul(q);

					const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, mockRand);
					expect(proof.verify(h1, h2, N)).toBe(true);
		});

				it('should verify with incrementally larger secret values', () => {
			const h1 = new BN(ec.g.getX());
			const h2 = new BN(ec.g.getY());
			const p = new BN('FFFF', 16);
			const q = new BN('FFFD', 16);
			const N = p.mul(q);

					const testSizes = [16, 32, 64, 128];
					
					for (const size of testSizes) {
						const x = new BN(crypto.randomBytes(Math.floor(size/8)));
						const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, mockRand);
						expect(proof.verify(h1, h2, N)).toBe(true);
					}
		});

				it('should handle boundary value secrets', () => {
			const h1 = new BN(ec.g.getX());
			const h2 = new BN(ec.g.getY());
					const p = new BN('FFFF', 16);
					const q = new BN('FFFD', 16);
					const N = p.mul(q);

					// Test with minimal valid secret
					const minX = new BN(2);
					const minProof = DLNProof.newDLNProof(h1, h2, minX, p, q, N, mockRand);
					expect(minProof.verify(h1, h2, N)).toBe(true);

					// Test with secret close to modulus
					const maxX = p.mul(q).subn(2);
					const maxProof = DLNProof.newDLNProof(h1, h2, maxX, p, q, N, mockRand);
					expect(maxProof.verify(h1, h2, N)).toBe(true);
				});

				it('should verify with different curve points', () => {
					// Use different points on the curve
					const P = ec.g.mul(new BN(123456789));
					const h1 = new BN(P.getX());
					const h2 = new BN(P.getY());
					
					const x = new BN('123456789', 16);
					const p = new BN('FFFF', 16);
					const q = new BN('FFFD', 16);
			const N = p.mul(q);

			const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, mockRand);
			expect(proof.verify(h1, h2, N)).toBe(true);
		});
				
				it('should verify proof with same parameters multiple times', () => {
					const h1 = new BN(ec.g.getX());
					const h2 = new BN(ec.g.getY());
					const x = new BN('123456789', 16);
					const p = new BN('FFFF', 16);
					const q = new BN('FFFD', 16);
					const N = p.mul(q);

					const proof = DLNProof.newDLNProof(h1, h2, x, p, q, N, mockRand);
					
					// Verify multiple times to ensure consistency
					for (let i = 0; i < 3; i++) {
						expect(proof.verify(h1, h2, N)).toBe(true);
					}
				});
			});

		}
	)
}
);