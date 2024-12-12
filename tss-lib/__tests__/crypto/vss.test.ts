import { Share, Create } from '../../crypto/VSS';
import { CurveParams } from '../../common/Types';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';

describe('VSS Tests', () => {
	let ec: EC;
	let curveParams: CurveParams;

	beforeAll(() => {
		ec = new EC('secp256k1');
		curveParams = {
			n: new BN(ec.curve.n),
			g: ec.g,
			curve: ec,
			p: new BN(ec.curve.p)
		};
	});

	const mockRandomSource = {
		randomBytes: (size: number) => crypto.randomBytes(size)
	};

	describe('Share Creation and Verification', () => {
		it('should create and verify valid shares', () => {
			const threshold = 2;
			const secret = new BN('123456789');
			const indexes = [
				new BN(1),
				new BN(2),
				new BN(3)
			];

			const [vs, shares] = Create(
				threshold,
				secret,
				indexes,
				curveParams.curve,
				mockRandomSource
			);

			// Verify each share
			shares.forEach(share => {
				expect(share.verify(curveParams.curve, threshold, vs)).toBe(true);
			});
		});

		it('should reject shares with invalid threshold', () => {
			const threshold = 2;
			const secret = new BN('123456789');
			const indexes = [new BN(1), new BN(2), new BN(3)];

			const [vs, shares] = Create(
				threshold,
				secret,
				indexes,
				curveParams.curve,
				mockRandomSource
			);

			shares.forEach(share => {
				expect(share.verify(curveParams.curve, threshold + 1, vs)).toBe(false);
			});
		});

		it('should reject duplicate party indexes', () => {
			const threshold = 2;
			const secret = new BN('123456789');
			const indexes = [new BN(1), new BN(1), new BN(2)];

			expect(() => Create(
				threshold,
				secret,
				indexes,
				curveParams.curve,
				mockRandomSource
			)).toThrow();
		});

		it('should reject threshold larger than number of parties', () => {
			const threshold = 4;
			const secret = new BN('123456789');
			const indexes = [new BN(1), new BN(2), new BN(3)];

			expect(() => Create(
				threshold,
				secret,
				indexes,
				curveParams.curve,
				mockRandomSource
			)).toThrow();
		});
	});
});