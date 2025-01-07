// __tests__/crypto/ecpoint.test.ts
import { ECPoint } from '../../crypto/ECPoint';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';

describe('ECPoint Tests', () => {
	let ec: EC;

	beforeAll(() => {
		ec = new EC('ed25519');
	});

	describe('Point Creation', () => {
		it('should create valid curve point', () => {
			const x = ec.g.getX();
			const y = ec.g.getY();
			const point = new ECPoint(ec, x, y);
			expect(point.isOnCurve()).toBe(true);
		});

		it('should reject invalid curve point', () => {
			const x = new BN(1);
			const y = new BN(1);
			expect(() => new ECPoint(ec, x, y)).toThrow();
		});

		it('should create point without validation', () => {
			const x = ec.g.getX();
			const y = ec.g.getY();
			const point = ECPoint.newECPointNoCurveCheck(ec, x, y);
			expect(point.isOnCurve()).toBe(true);
		});
	});

	describe('Point Operations', () => {
		let basePoint: ECPoint;

		beforeEach(() => {
			basePoint = new ECPoint(ec, ec.g.getX(), ec.g.getY());
		});

		it('should add two points', () => {
			const p1 = basePoint;
			const p2 = basePoint;
			const sum = p1.add(p2);
			expect(sum.isOnCurve()).toBe(true);

			// 2G should match direct doubling
			const double = basePoint.scalarMult(new BN(2));
			expect(sum.equals(double)).toBe(true);
		});

		it('should multiply point by scalar', () => {
			const k = new BN(3);
			const result = basePoint.scalarMult(k);
			expect(result.isOnCurve()).toBe(true);

			// 3G should match adding G three times
			const sum = basePoint.add(basePoint).add(basePoint);
			expect(result.equals(sum)).toBe(true);
		});

		it('should perform base point multiplication', () => {
			const k = new BN(2);
			const result = ECPoint.scalarBaseMult(ec, k);
			expect(result.isOnCurve()).toBe(true);

			// 2G should match doubling generator
			const double = basePoint.scalarMult(k);
			expect(result.equals(double)).toBe(true);
		});
	});

	describe('Point Properties', () => {
		it('should correctly compare points', () => {
			const p1 = new ECPoint(ec, ec.g.getX(), ec.g.getY());
			const p2 = new ECPoint(ec, ec.g.getX(), ec.g.getY());
			const p3 = p1.scalarMult(new BN(2));

			expect(p1.equals(p2)).toBe(true);
			expect(p1.equals(p3)).toBe(false);
			expect(p1.equals(null)).toBe(false);
		});

		it('should handle curve assignment', () => {
			const point = new ECPoint(ec, ec.g.getX(), ec.g.getY());
			const newPoint = point.setCurve(ec);
			expect(newPoint.getCurve()).toBe(ec);
			expect(newPoint.isOnCurve()).toBe(true);
		});
	});
});

describe('ECPoint Edwards Curve Tests', () => {
    let ec: EC;
    let basePoint: ECPoint;

    beforeAll(() => {
        // Initialize Ed25519 curve
        ec = new EC('ed25519');
        // Create base point without validation (we know G is valid)
        basePoint = ECPoint.newECPointNoCurveCheck(ec, ec.g.getX(), ec.g.getY());
    });

    describe('Edwards Point Creation', () => {
        test('should create valid edwards base point', () => {
            const point = ECPoint.newECPointNoCurveCheck(ec, ec.g.getX(), ec.g.getY());
            expect(point.isOnCurve()).toBe(true);
        });

        test('should handle scalar multiplication result', () => {
            // 2G = G + G
            const doubleG = basePoint.scalarMult(new BN(2));
            expect(doubleG.isOnCurve()).toBe(true);
        });

        test('should perform point addition', () => {
            const P = basePoint;
            const Q = basePoint.scalarMult(new BN(2));
            const sum = P.add(Q);
            expect(sum.isOnCurve()).toBe(true);
        });
    });

    describe('Point Properties', () => {
        test('should compare points correctly', () => {
            const P = ECPoint.newECPointNoCurveCheck(ec, ec.g.getX(), ec.g.getY());
            const Q = ECPoint.newECPointNoCurveCheck(ec, ec.g.getX(), ec.g.getY());
            expect(P.equals(Q)).toBe(true);
        });

        test('should validate curve point', () => {
            const P = ECPoint.newECPointNoCurveCheck(ec, ec.g.getX(), ec.g.getY());
            expect(P.isOnCurve()).toBe(true);
        });
    });

    describe('Scalar Operations', () => {
        test('should perform scalar base multiplication', () => {
            const k = new BN(2);
            const R = ECPoint.scalarBaseMult(ec, k);
            const expected = basePoint.scalarMult(k);
            expect(R.equals(expected)).toBe(true);
        });
    });
});