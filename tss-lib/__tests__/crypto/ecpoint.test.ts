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

describe('ECPoint (ECDSA/secp256k1)', () => {
    let secp256k1: EC;
    
    beforeEach(() => {
        secp256k1 = new EC('secp256k1');
    });

    describe('Construction', () => {
        test('should create valid secp256k1 point', () => {
            const point = new ECPoint(
                secp256k1,
                secp256k1.g.getX(),
                secp256k1.g.getY(),
                true,
                'weierstrass'
            );
            expect(point.isValid()).toBe(true);
        });

        test('should reject invalid curve point', () => {
            expect(() => {
                new ECPoint(
                    secp256k1,
                    new BN(1),
                    new BN(1),
                    true,
                    'weierstrass'
                );
            }).toThrow();
        });
    });

    describe('Point Operations', () => {
        test('should perform scalar multiplication', () => {
            const G = new ECPoint(
                secp256k1,
                secp256k1.g.getX(),
                secp256k1.g.getY(),
                true,
                'weierstrass'
            );
            const scalar = new BN(2);
            const double = G.mul(scalar);
            expect(double.isValid()).toBe(true);
            expect(double.equals(G.add(G))).toBe(true);
        });

        test('should add points correctly', () => {
            const G = new ECPoint(
                secp256k1,
                secp256k1.g.getX(),
                secp256k1.g.getY(),
                true,
                'weierstrass'
            );
			const P = G.scalarMult(new BN(2));
			const Q = G.scalarMult(new BN(3));
			const sum = P.add(G);
            expect(sum.equals(Q)).toBe(true);
        });

        test('should perform base point multiplication', () => {
            const scalar = new BN(5);
            const point = ECPoint.scalarBaseMult(secp256k1, scalar, 'weierstrass');
            const expected = new ECPoint(
                secp256k1,
                secp256k1.g.getX(),
                secp256k1.g.getY(),
                true,
                'weierstrass'
            ).mul(scalar);
            expect(point.equals(expected)).toBe(true);
        });
    });

    describe('Point Validation', () => {
        test('should detect points at infinity', () => {
            const G = new ECPoint(
                secp256k1,
                secp256k1.g.getX(),
                secp256k1.g.getY(),
                true,
                'weierstrass'
            );
            const n = secp256k1.n as BN;
            const infinity = G.mul(n);
            expect(infinity.isInfinity()).toBe(true);
        });

        test('should validate points on curve', () => {
            const G = new ECPoint(
                secp256k1,
                secp256k1.g.getX(),
                secp256k1.g.getY(),
                true,
                'weierstrass'
            );
            expect(G.isOnCurve()).toBe(true);
        });
    });

    describe('Serialization', () => {
        test('should flatten and unflatten points', () => {
            const G = new ECPoint(
                secp256k1,
                secp256k1.g.getX(),
                secp256k1.g.getY(),
                true,
                'weierstrass'
            );
            const points = [G, G.mul(new BN(2))];
            const flattened = ECPoint.flattenECPoints(points);
            const restored = ECPoint.unFlattenECPoints(flattened, secp256k1);
            expect(restored[0].equals(points[0])).toBe(true);
            expect(restored[1].equals(points[1])).toBe(true);
        });
    });
});