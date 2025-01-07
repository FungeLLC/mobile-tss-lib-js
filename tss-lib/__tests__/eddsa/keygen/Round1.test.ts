import { Round1, KGRound1Message } from '../../../eddsa/keygen/Round1';
import { KeygenParams } from '../../../eddsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../eddsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../eddsa/keygen/LocalTempData';
import { TssError } from '../../../common/TssError';
import { PartyID } from '../../../eddsa/keygen/interfaces';
import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import { ParsedMessage } from '../../../eddsa/keygen/interfaces';
import { RandomSource } from 'tss-lib/common/Types';




describe('Round1', () => {
	let params: KeygenParams;
	let data: LocalPartySaveData;
	let temp: LocalTempData;
	let out: jest.Mock;
	let end: jest.Mock;
	let round1: Round1;

	beforeEach(() => {
		params = {
			partyID: () => ({ index: 1, arrayIndex: 0 } as PartyID),
			partyIDInstance: new PartyID(1, '1'),
			parties: [
				{ index: 1, moniker: '1', keyInt: () => new BN(1), arrayIndex: 0 },
				{ index: 2, moniker: '2', keyInt: () => new BN(2), arrayIndex: 1 },
				{ index: 3, moniker: '3', keyInt: () => new BN(3), arrayIndex: 2 }
			],
				threshold: 2,
			totalParties: 3,
			partyCount: () => 3,
			ec: new EC('ed25519').curve,
			ecParams: new EC('ed25519').curve,
			rand: { randomBytes: (size: number) => crypto.randomBytes(size) } as RandomSource
		};

		data = new LocalPartySaveData(params.partyCount());
		temp = new LocalTempData(params.partyCount());
		out = jest.fn();
		end = jest.fn();
		round1 = new Round1(params, data, temp, out, end);
	});

	describe('Initialization', () => {
		test('should initialize with correct round number', () => {
			expect(round1.number).toBe(1);
		});

		test('should initialize ok array with correct length', () => {
			expect(round1['ok'].length).toBe(params.totalParties);
		});
	});

	describe('Start Validation', () => {
		test('should not start twice', async () => {
			await round1.start();
			const error = await round1.start();
			expect(error?.message).toBe('round already started');
		});

	});

	describe('VSS and Commitment', () => {
		test('should generate ui within valid curve order range', async () => {
			await round1.start();
			expect(temp.ui).toBeDefined();
			expect(temp.ui.gt(new BN(0))).toBe(true);
			expect(temp.ui.lt(params.ec.n)).toBe(true);
		});

		test('should generate correct number of VSS coefficients', async () => {
			await round1.start();
			expect(temp.vs).toBeDefined();
			expect(temp.vs.length).toBe(params.threshold + 1);
		});

		test('each VSS share should be within curve order', async () => {
			await round1.start();
			expect(temp.shares).toBeDefined();
			temp.shares.forEach(share => {
				expect(share.share.gt(new BN(0))).toBe(true);
				expect(share.share.lt(params.ec.n)).toBe(true);
			});
		});

		test('should generate shares for all parties', async () => {
			await round1.start();
			expect(temp.shares).toBeDefined();
			expect(temp.shares.length).toBe(params.parties.length);
			temp.shares.forEach((share, i) => {
				expect(share).toBeDefined();
			});
		});

		test('VSS commitment points should be on curve', async () => {
			await round1.start(); 
			expect(temp.vs).toBeDefined();
			temp.vs.forEach(point => {
				expect(point.isValid()).toBe(true);
				expect(point.isInfinity()).toBe(false);
			});
		});

		test('should store commitment data', async () => {
			await round1.start();
			expect(temp.deCommitPolyG).toBeDefined();
			expect(data.shareID).toBeDefined();
		});

		test('should store party IDs', async () => {
			await round1.start();
			expect(data.ks).toHaveLength(params.totalParties);
		});
	});

	describe('Message Handling', () => {
		test('should broadcast commitment message', async () => {
			await round1.start();
			expect(out).toHaveBeenCalledTimes(1);
			const msg = out.mock.calls[0][0] as KGRound1Message;
			expect(msg.isBroadcast).toBe(true);
			expect(msg.getFrom().index).toBe(1);
		});

		test('should reject invalid message type', () => {
			const [success, error] = round1.update({} as ParsedMessage);
			expect(success).toBe(false);
			// expect(error?.message).toBe('unexpected message type in round 1');
		});

		test('should reject message from invalid party index', () => {
			const msg = new KGRound1Message(
				{ index: params.totalParties + 1, arrayIndex: params.totalParties } as PartyID,
				Buffer.from([])
			);
			const [success, error] = round1.update(msg);
			expect(success).toBe(false);
			expect(error?.message).toContain('invalid party array index');
		});

		test('should accept valid message', () => {
			const msg = new KGRound1Message(
				{ index: 2 } as PartyID,
				Buffer.from([1, 2, 3])
			);
			const [success, error] = round1.update(msg);
			expect(success).toBe(true);
			expect(error).toBeNull();
		});
	});

	describe('Round Progression', () => {
		test('should not proceed until all messages received', async () => {
			await round1.start();
			expect(round1.canProceed()).toBe(false);
		});

		test('should proceed when all messages received', async () => {
			await round1.start();

			// Send messages from other parties only (not from self)
			for (let i = 1; i <= params.totalParties; i++) {
				if (i === params.partyID().index) continue; // Skip self

				const msg = new KGRound1Message(
					{
						index: i,
						moniker: i.toString(),
						arrayIndex: i - 1
					} as PartyID,
					Buffer.from([1, 2, 3])
				);
				const [success, error] = round1.update(msg);
				expect(success).toBe(true);
				expect(error).toBeNull();
			}

			expect(round1.canProceed()).toBe(true);
		});
	});
});