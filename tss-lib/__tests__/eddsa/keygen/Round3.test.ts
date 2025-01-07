import { Round3, KGRound3Message } from '../../../eddsa/keygen/Round3';
import { KeygenParams } from '../../../eddsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../eddsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../eddsa/keygen/LocalTempData';
import { PartyID } from '../../../eddsa/keygen/interfaces';
import { ECPoint } from '../../../crypto/ECPoint';
import { Share } from '../../../crypto/VSS';
import BN from 'bn.js';

describe('Round3', () => {
	let params: KeygenParams;
	let data: LocalPartySaveData;
	let temp: LocalTempData;
	let out: jest.Mock;
	let end: jest.Mock;
	let round3: Round3;

	beforeEach(() => {
		params = {
			partyID: () => ({ index: 1, arrayIndex: 0 } as PartyID),
			totalParties: 3,
			threshold: 2,
			parties: [
				{ index: 1, arrayIndex: 0, keyInt: () => new BN(1) },
				{ index: 2, arrayIndex: 1, keyInt: () => new BN(2) },
				{ index: 3, arrayIndex: 2, keyInt: () => new BN(3) }
			],
			ec: { 
				n: new BN(7), 
				curve: { 
					add: jest.fn(), 
					mul: jest.fn(),
					validate: jest.fn(),
					point: jest.fn().mockReturnValue({ validate: jest.fn() }),
					g: { x: new BN(1), y: new BN(1), curve: { validate: () => true, point: () => ({ validate: () => true }) } }
				} 
			}
		} as any;
		data = new LocalPartySaveData(params.totalParties);
		temp = new LocalTempData(params.totalParties);
		out = jest.fn();
		end = jest.fn();
		round3 = new Round3(params, data, temp, out, end);
	});

	test('should initialize with correct round number', () => {
		expect(round3.number).toBe(3);
	});

	test('should not proceed without Round2 messages', () => {
		expect(round3.canProceed()).toBe(false);
	});

	test('should handle Round3 message correctly', () => {
		const msg = new KGRound3Message({ index: 2, arrayIndex: 1 } as PartyID);
		const [success, error] = round3.update(msg);
		expect(success).toBe(true);
		expect(error).toBeNull();
	});

	test('should reject invalid party index', () => {
		const msg = new KGRound3Message({ index: 99, arrayIndex: 98 } as PartyID);
		const [success, error] = round3.update(msg);
		expect(success).toBe(false);
		expect(error?.message).toBe('invalid party array index');
	});

	test('should complete round when all messages received', async () => {
		// Setup Round2 messages
		temp.kgRound2Message1s = Array(params.totalParties).fill({
			content: () => ({
				unmarshalShare: () => new BN(123)
			})
		});

		// Setup shares
		temp.shares = [
			new Share(2, new BN(1), new BN(1)),
			new Share(2, new BN(2), new BN(2)),
			new Share(2, new BN(3), new BN(3))
		];

		// Setup VSS data 
		temp.vs = [
			new ECPoint(params.ec.curve, new BN(1), new BN(1))
		];

		await round3.start();

		temp.kgRound3Messages = Array(params.totalParties).fill(null);
		for (let i = 1; i <= params.totalParties; i++) {
			if (i === params.partyID().index) continue;
			const msg = new KGRound3Message({
				index: i,
				arrayIndex: i - 1
			} as PartyID);
			round3.update(msg);
		}

		expect(round3.isComplete()).toBe(true);
		expect(data.eddsaPub).toBeDefined();
	});
});