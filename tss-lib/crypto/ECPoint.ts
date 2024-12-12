import { ec as EC } from 'elliptic';
import BN from 'bn.js';

export class ECPoint {
	private coords: [BN, BN];

	constructor(private curve: EC, X: BN, Y: BN) {
		if (!isOnCurve(curve, X, Y)) {
			throw new Error("NewECPoint: the given point is not on the elliptic curve");
		}
		this.coords = [X, Y];
	}

	static newECPointNoCurveCheck(curve: EC, X: BN, Y: BN): ECPoint {
		const point = new ECPoint(curve, X, Y);
		return point;
	}

	public X(): BN {
		return this.coords[0].clone();
	}

	public Y(): BN {
		return this.coords[1].clone();
	}

	public add(p1: ECPoint): ECPoint {
		const p1Point = this.curve.curve.point(this.X(), this.Y());
		const p2Point = this.curve.curve.point(p1.X(), p1.Y());
		const result = p1Point.add(p2Point);
		return new ECPoint(this.curve, result.getX(), result.getY());
	}

	public scalarMult(k: BN): ECPoint {
		const point = this.curve.curve.point(this.X(), this.Y());
		const result = point.mul(k);
		return new ECPoint(this.curve, result.getX(), result.getY());
	}

	public static scalarBaseMult(curve: EC, k: BN): ECPoint {
		const result = curve.g.mul(k);
		return new ECPoint(curve, result.getX(), result.getY());
	}

	public isOnCurve(): boolean {
		return isOnCurve(this.curve, this.coords[0], this.coords[1]);
	}

	public getCurve(): EC {
		return this.curve;
	}

	public equals(p2: ECPoint | null): boolean {
		if (!p2) return false;
		return this.X().eq(p2.X()) && this.Y().eq(p2.Y());
	}

	public setCurve(curve: EC): ECPoint {
		this.curve = curve;
		return this;
	}

	public static flattenECPoints(points: ECPoint[]): BN[] {

		return points.reduce((acc: BN[], point: ECPoint) => {

			acc.push(point.X());

			acc.push(point.Y());

			return acc;

		}, []);

	}

	public static unFlattenECPoints(flattenedPoints: BN[], curve: EC): ECPoint[] {
		const points: ECPoint[] = [];
		for (let i = 0; i < flattenedPoints.length; i += 2) {
			points.push(new ECPoint(curve, flattenedPoints[i], flattenedPoints[i + 1]));
		}
		return points;
	}

}

function isOnCurve(c: EC, x: BN, y: BN): boolean {
	if (!x || !y) return false;
	try {
		const point = c.curve.point(x, y);
		return point.validate();
	} catch {
		return false;
	}
}