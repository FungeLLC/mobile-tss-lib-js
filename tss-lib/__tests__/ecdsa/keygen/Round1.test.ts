import { Round1 } from '../../../ecdsa/keygen/Round1';
import { KeygenParams } from '../../../ecdsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../ecdsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../ecdsa/keygen/LocalTempData';
import { ECPoint } from '../../../crypto/ECPoint';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import * as crypto from 'crypto';
import { RandomSource } from '../../../common/Types';

describe('Round1 (ECDSA)', () => {
	let params: KeygenParams;
	let data: LocalPartySaveData;
	let temp: LocalTempData;
	let out: jest.Mock;
	let end: jest.Mock;
	let round1: Round1;
	let secp256k1: EC;

	beforeEach(() => {
		secp256k1 = new EC('secp256k1');
		const mockParties = Array.from({ length: 3 }, (_, i) => ({
			index: i + 1,
			moniker: `party${i + 1}`,
			arrayIndex: i,
			keyInt: () => new BN(i + 1)
		}));

		params = new KeygenParams({
			partyCount: 3,
			threshold: 2,
			curve: {
				n: secp256k1.n as BN,
				g: secp256k1.g,
				p: secp256k1.curve.p,
				curve: secp256k1
			},
			parties: mockParties,
			partyID: () => mockParties[0],
			randomSource: { randomBytes: (size: number) => crypto.randomBytes(size) } as RandomSource,
			proofParams: { iterations: 1, hashLength: 32, primeBits: 256 }
		});

		data = new LocalPartySaveData(params.partyCount());
		temp = new LocalTempData(params.partyCount());
		temp.shares = Array(params.partyCount()).fill(null);
		out = jest.fn();
		end = jest.fn();
		round1 = new Round1(params, data, temp, out, end);
		jest.clearAllMocks();
	});

	describe('Initialization', () => {
		test('should initialize with round number 1', () => {
			expect(round1.number).toBe(1);
		});

		test('should initialize ok array with correct party count', () => {
			expect(round1['ok'].length).toBe(params.totalParties);
		});
	});

	describe('Round State', () => {
		test('should not allow double start', async () => {
			await round1.start();
			const error = await round1.start();
			expect(error?.message).toBe('round already started');
		});

		test('should not be able to proceed before receiving all messages', async () => {
			await round1.start();
			expect(round1.canProceed()).toBe(false);
		});
	});

	describe('VSS Generation', () => {
		test('should generate ui within secp256k1 order', async () => {
			await round1.start();
			expect(temp.ui).toBeDefined();
			expect(temp.ui.gt(new BN(0))).toBe(true);
			if (!secp256k1.n) {
				throw new Error('secp256k1 curve not initialized');
			}
			expect(temp.ui.lt(secp256k1.n)).toBe(true);
		});

		test('should generate threshold+1 VSS coefficients', async () => {
			await round1.start();
			expect(temp.vs).toBeDefined();
			expect(temp.vs.length).toBe(params.threshold + 1);
		});

		test('should generate shares for all parties', async () => {
			await round1.start();
			expect(temp.shares).toBeDefined();
			expect(temp.shares.length).toBe(params.totalParties);
		});

		test('each share should be within secp256k1 order', async () => {
			const result = await round1.start();

			//check if an error
			if (result instanceof Error) {
				throw result;
			}

			expect(temp.shares).toBeDefined();

			temp.shares.forEach(share => {
				expect(share.share.gt(new BN(0))).toBe(true);
				if (!secp256k1.n){
					throw new Error('secp256k1 curve not initialized');
				}
				expect(share.share?.lt(secp256k1.n as BN )).toBe(true);
			});
		});
	});

	describe('Commitment Generation', () => {
		test('should generate valid commitment points', async () => {
			await round1.start();
			expect(temp.vs).toBeDefined();
			expect(temp.vs.filter(point => point !== null).length).toBeGreaterThan(0);
			temp.vs.filter(point => point !== null).forEach(point => {
				expect(point).toBeDefined();
				expect(Object.getPrototypeOf(point) === ECPoint.prototype).toBe(true);
				expect(point.isValid()).toBe(true);
			});

		});

		test('should generate valid decommitment data', async () => {
			await round1.start();
			expect(temp.deCommitPolyG).toBeDefined();
			expect(Array.isArray(temp.deCommitPolyG)).toBe(true);
		});
	});

	describe('Message Handling', () => {
		test('should broadcast commitment message', async () => {
			await round1.start();
			expect(out).toHaveBeenCalled();
			const msg = out.mock.calls[0][0];
			expect(msg.isBroadcast).toBe(true);
		});

		test('should handle incoming commitment messages', async () => {
			await round1.start();
			const msg = {
				getFrom: () => ({ index: 2, arrayIndex: 1,
					moniker: 'party2',
					keyInt: () => new BN(2)
				}),
				content: () => ({ commitment: Buffer.alloc(32) }),
				isBroadcast: true,
				wireBytes: Buffer.alloc(0)
				
			};
			const [ok, err] = round1.update(msg);
			expect(ok).toBe(true);
			expect(err).toBeNull();
		});
	});
});