import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';

export class ECPoint {
    private weierstrassXY?: [BN, BN];
    private edwardsPoint?: any; // elliptic 'Point' for edwards
    public curve: EC;
	public curveType: string;

    constructor(curve: EC, X: BN, Y: BN, validate: boolean = true, curveType: string = '') {

        this.curve = curve;

        if(curveType !== '') {
		    this.curveType = curveType;
        } else if (curve.curve.type){
            this.curveType = curve.curve.type;
        }else {
            throw new Error('ECPoint: curveType not provided and curve does not have curveType');
        }



        if (this.curveType === 'edwards') {
            // Directly use internal representation
			this.edwardsPoint = curve.g.curve.point(X, Y);
            if (validate && !this.edwardsPoint.validate()) {
                throw new Error('NewECPoint: the given point is not on the edwards curve');
            }
        } else {
            // Weierstrass
            this.weierstrassXY = [X, Y];
            if (validate) {
                const point = this.curve.g.curve.point(X, Y);
                if (!point.validate()) {
                    throw new Error('NewECPoint: the given point is not on the elliptic curve');
                }
            }
        }
    }

    public static newECPointNoCurveCheck(curve: EC, X: BN, Y: BN): ECPoint {
        return new ECPoint(curve, X, Y, false);
    }

    public X(): BN {
        if (this.curveType === 'edwards') {
            return this.edwardsPoint.getX();
        }
        return this.weierstrassXY![0].clone();
    }

    public Y(): BN {
        if (this.curveType === 'edwards') {
            return this.edwardsPoint.getY();
        }
        return this.weierstrassXY![1].clone();
    }

    public isInfinity(): boolean {
        if (this.curveType === 'edwards') {
            return this.edwardsPoint.isInfinity();
        }
        const point = this.curve.curve.point(this.X(), this.Y());
        return point.isInfinity();
    }

    public isValid(): boolean {

		return ECPoint.newECPointNoCurveCheck(this.curve, this.X(), this.Y()).isOnCurve();
    }

    public add(p1: ECPoint): ECPoint {
        if (this.curveType === 'edwards') {
            const sum = this.edwardsPoint.add(p1.edwardsPoint);
            return ECPoint.newECPointNoCurveCheck(this.curve, sum.getX(), sum.getY());
        }
        const p1Point = this.curve.curve.point(this.X(), this.Y());
        const p2Point = this.curve.curve.point(p1.X(), p1.Y());
        const result = p1Point.add(p2Point);
        return new ECPoint(this.curve, result.getX(), result.getY(), false, 'weierstrass');
    }

    public scalarMult(k: BN): ECPoint {
        const reduced = k.umod(this.curve.n as BN);
        if (this.curveType === 'edwards') {
            // Multiply internal edwards point
            const result = this.edwardsPoint.mul(reduced);
            return ECPoint.newECPointNoCurveCheck(this.curve, result.getX(), result.getY());
        }
        // Weierstrass
        const point = this.curve.curve.point(this.X(), this.Y());
        const mulResult = point.mul(reduced);

        if (mulResult.isInfinity()) {
            return mulResult;
        }

        return new ECPoint(this.curve, mulResult.getX(), mulResult.getY(), false, 'weierstrass');
    }

    public static scalarBaseMult(curve: EC, k: BN, curveType: string = ''): ECPoint {
        //look at which type of object it is
        if ( curve.curve.type === 'edwards') {
            curveType = 'edwards';
        }else {
            curveType = 'weierstrass';
        }
    

        const reduced = k.umod(curve.n as BN);
        const result = curve.g.mul(reduced);

        if (curveType === 'edwards') {
            const x = typeof result.getX === 'function' ? result.getX() : result.X();
            const y = typeof result.getY === 'function' ? result.getY() : result.Y();
            return ECPoint.newECPointNoCurveCheck(curve, x, y);
        }
        // Weierstrass
        return new ECPoint(curve, result.getX(), result.getY(), false, 'weierstrass');
    }

    public isOnCurve(): boolean {
        if (this.curveType === 'edwards') {
            // Validate internal edwards point
            return this.edwardsPoint.validate();
        }
        // Weierstrass
        try {
            const point = this.curve.curve.point(this.X(), this.Y());
            return point.validate();
        } catch (error: unknown) {
            if (error instanceof Error) {
                console.debug('Point validation failed:', error.message);
            }
            return false;
        }
    }

    public getCurve(): EC {
        return this.curve;
    }

    public mul(k: BN): ECPoint {
        return this.scalarMult(k);
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