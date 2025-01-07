import BN from 'bn.js';
import { ProofMod } from '../../crypto/MODProof';

describe('MODProof', () => {
	const session = Buffer.from('test-session');
	const p = new BN('F22B3C8A51B42806B1ED5E6BE31068C5E8C4F54486BB1C77F45C974101E1F231', 16);
	const q = new BN('EC1A12B1A514A0CD8D667AF87972D6601460D12F6E11AB51C5199CD67E832899', 16);
	const n = p.mul(q);

	describe('newProof', () => {
			it('should generate valid proof', async () => {
			const proof = await ProofMod.newProof(session, n, p, q);
			expect(await proof.verify(session, n)).toBe(true);
		});
	});

	describe('fromBytes/toBytes', () => {
		it('should serialize and deserialize proof correctly', async () => {
			const proof = await ProofMod.newProof(session, n, p, q);
			const bytes = proof.toBytes();
			const deserialized = ProofMod.fromBytes(bytes);
			expect(await deserialized.verify(session, n)).toBe(true);
		});

		it('should throw error if incorrect number of byte parts', () => {
			expect(() => ProofMod.fromBytes([])).toThrow();
		});
	});

	describe('verify', () => {
		it('should fail for invalid W', async () => {
			const proof = await ProofMod.newProof(session, n, p, q);
			proof.W = new BN(1);
			expect(await proof.verify(session, n)).toBe(false);
		});

		it('should fail if N is even', async () => {
			console.log('Starting test: should fail if N is even');
			const proof = await ProofMod.newProof(session, n, p, q);
			const evenN = n.addn(1);
			console.log('Calling verify with even N:', evenN.toString());
			const result = await proof.verify(session, evenN);
			console.log('Verification result:', result);
			expect(result).toBe(false);
		});

		it('should fail for invalid X values', async () => {
			const proof = await ProofMod.newProof(session, n, p, q);
			proof.X[0] = new BN(0);
			expect(await proof.verify(session, n)).toBe(false);
		});
	});

	describe('validateBasic', () => {
		it('should validate correct proof', async () => {
			const proof = await ProofMod.newProof(session, n, p, q);
			expect(proof.validateBasic()).toBe(true);
		});

		it('should fail for null values', async () => {
			const proof = await ProofMod.newProof(session, n, p, q);
			proof.W = null as any;
			expect(proof.validateBasic()).toBe(false);
		});
	});
});