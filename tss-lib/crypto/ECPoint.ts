import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';

class ECPoint {
	private curve: EC;
	private coords: [BN, BN];

	private static eight = new BN(8);
	private static eightInv: BN; // Will be initialized with curve-specific value

	constructor(curve: EC, X: BN, Y: BN) {
		if (!isOnCurve(curve, X, Y)) {
			throw new Error("NewECPoint: the given point is not on the elliptic curve");
		}
		this.curve = curve;
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
		const point = this.curve.g.add(
			{ x: this.X(), y: this.Y() }
		).add(
			{ x: p1.X(), y: p1.Y() }
		);
		return new ECPoint(this.curve, point.getX(), point.getY());
	}

	public scalarMult(k: BN): ECPoint {
		const point = this.curve.g.mul(k);
		return new ECPoint(this.curve, point.getX(), point.getY());
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

	public validateBasic(): boolean {
		return this.coords[0] != null && this.coords[1] != null && this.isOnCurve();
	}

	public eightInvEight(): ECPoint {
		return this.scalarMult(ECPoint.eight).scalarMult(ECPoint.eightInv);
	}

	public static scalarBaseMult(curve: EC, k: BN): ECPoint {
		const point = curve.g.mul(k);
		return new ECPoint(curve, point.getX(), point.getY());
	}

	public static flattenECPoints(points: ECPoint[]): BN[] {
		if (!points) {
			throw new Error("FlattenECPoints encountered a nil in slice");
		}
		const flat: BN[] = [];
		for (const point of points) {
			if (!point || !point.coords[0] || !point.coords[1]) {
				throw new Error("FlattenECPoints found nil point/coordinate");
			}
			flat.push(point.coords[0]);
			flat.push(point.coords[1]);
		}
		return flat;
	}

	public static unflattenECPoints(curve: EC, coords: BN[], noCurveCheck: boolean = false): ECPoint[] {
		if (!coords || coords.length % 2 !== 0) {
			throw new Error("UnFlattenECPoints expected coords length divisible by 2");
		}

		const points: ECPoint[] = [];
		for (let i = 0; i < coords.length; i += 2) {
			const point = noCurveCheck ?
				ECPoint.newECPointNoCurveCheck(curve, coords[i], coords[i + 1]) :
				new ECPoint(curve, coords[i], coords[i + 1]);
			points.push(point);
		}

		return points;
	}

	public static unmarshalPoints(buffer: Buffer): ECPoint[] {
		const points: ECPoint[] = [];
		const curve = new EC('secp256k1'); // Use secp256k1 as default curve
		let offset = 0;

		while (offset < buffer.length) {
			const xLen = buffer.readUInt32LE(offset);
			offset += 4;
			const x = new BN(buffer.slice(offset, offset + xLen));
			offset += xLen;
			const yLen = buffer.readUInt32LE(offset);
			offset += 4;
			const y = new BN(buffer.slice(offset, offset + yLen));

			points.push(new ECPoint(curve, x, y));
			offset += yLen;
		}

		return points;
	}

	public serialize(): Buffer {
		const x = this.X().toArrayLike(Buffer);
		const y = this.Y().toArrayLike(Buffer);
		const xLen = Buffer.alloc(4);
		xLen.writeUInt32LE(x.length);
		const yLen = Buffer.alloc(4);
		yLen.writeUInt32LE(y.length);
		return Buffer.concat([xLen, x, yLen, y]);
	}

	public static deserialize(buf: Buffer): ECPoint {
		let offset = 0;
		const xLen = buf.readUInt32LE(offset);
		offset += 4;
		const x = new BN(buf.slice(offset, offset + xLen));
		offset += xLen;
		const yLen = buf.readUInt32LE(offset);
		offset += 4;
		const y = new BN(buf.slice(offset, offset + yLen));

		// Use secp256k1 as default curve
		const curve = new EC('secp256k1');
		return new ECPoint(curve, x, y);
	}

	public toJSON(): any {
		return {
			curve: this.curve.curve.type,
			coords: [this.coords[0].toString(), this.coords[1].toString()]
		};
	}

	public static fromJSON(json: any): ECPoint {
		const coords = [new BN(json.coords[0]), new BN(json.coords[1])];
		const curve = new EC(json.curve);
		return new ECPoint(curve, coords[0], coords[1]);
	}
}

function isOnCurve(c: EC, x: BN, y: BN): boolean {
	if (!x || !y) return false;
	return c.curve.validate({ x, y });
}

export { ECPoint };