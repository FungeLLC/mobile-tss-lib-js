import { Round4 } from '../../../eddsa/keygen/Round4';
import { KeygenParams } from '../../../eddsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../eddsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../eddsa/keygen/LocalTempData';
import { PartyID } from '../../../eddsa/keygen/interfaces';
import { ECPoint } from '../../../crypto/ECPoint';
import BN from 'bn.js';

describe('Round4', () => {
	let params: KeygenParams;
	let data: LocalPartySaveData;
	let temp: LocalTempData;
	let out: jest.Mock;
	let end: jest.Mock;
	let round4: Round4;

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
					n: new BN(7),
					add: jest.fn(), 
					mul: () => new ECPoint(params.ec.curve, new BN(1), new BN(2)),
					validate: jest.fn(),
					point: jest.fn().mockReturnValue({ validate: jest.fn() }),
					g: { x: new BN(1), y: new BN(1), curve: { validate: () => true, point: () => ({ validate: () => true,
						getX: () => new BN(1), getY: () => new BN(1) }) } }
					
					
				} 
			}
		} as any;
		data = new LocalPartySaveData(params.totalParties);
		temp = new LocalTempData(params.totalParties);
		out = jest.fn();
		end = jest.fn();
		round4 = new Round4(params, data, temp, out, end);
	});

	test('should initialize with round number 4', () => {
		expect(round4.number).toBe(4);
	});

	test('should require eddsaPub to be set', async () => {
		const error = await round4.start();
		expect(error?.message).toBe('ed25519 public key not set');
	});

	test('should verify final key successfully', async () => {
		// Setup mock public key and share
		data.eddsaPub = new ECPoint(params.ec.curve, new BN(1), new BN(2));
		data.xi = new BN(1);

		// Mock successful key verification
		const mockPoint = new ECPoint(params.ec.curve, new BN(1), new BN(2));
		params.ec.curve.g.mul = jest.fn().mockReturnValue(mockPoint);
		mockPoint.equals = jest.fn().mockReturnValue(true);
		data.eddsaPub.equals = jest.fn().mockReturnValue(true);

		const error = await round4.start();
		expect(error).toBeNull();
		expect(end).toHaveBeenCalled();
	});

	test('should fail if final key verification fails', async () => {
		data.eddsaPub = new ECPoint(params.ec.curve, new BN(1), new BN(2));
		data.xi = new BN(123);

		// Mock failed key verification
		const mockPoint = new ECPoint(params.ec.curve, new BN(1), new BN(2));
		params.ec.curve.g.mul = jest.fn().mockReturnValue(mockPoint);
		mockPoint.equals = jest.fn().mockReturnValue(false);
		data.eddsaPub.equals = jest.fn().mockReturnValue(false);

		const error = await round4.start();
		expect(error?.message).toBe('final key verification failed');
	});

	test('should not start twice', async () => {
		await round4.start();
		const error = await round4.start();
		expect(error?.message).toBe('round already started');
	});

	test('should reject unexpected messages', () => {
		const [success, error] = round4.update({ getFrom: () => 1 } as any);
		expect(success).toBe(false);
	});
});