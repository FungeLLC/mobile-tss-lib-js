import { BigInteger } from 'jsbn';
import BN from 'bn.js';

type BigIntType = BigInteger | BN;

class ModInt {
	private mod: BigIntType;

	constructor(mod: BigIntType) {
		this.mod = mod;
	}

	private toBN(value: BigIntType): BN {
		return BN.isBN(value) ? value : new BN(value.toString(16), 16);
	}

	private toBigInteger(value: BigIntType): BigInteger {
		return BN.isBN(value) ? new BigInteger(value.toString(16), 16) : value;
	}

	add(x: BigIntType, y: BigIntType): BigIntType {
		const result = this.toBN(x).add(this.toBN(y));
		return result.mod(this.toBN(this.mod));
	}

	sub(x: BigIntType, y: BigIntType): BigIntType {
		const result = this.toBN(x).sub(this.toBN(y));
		return result.mod(this.toBN(this.mod));
	}

	div(x: BigIntType, y: BigIntType): BigIntType {
		const result = this.toBN(x).div(this.toBN(y));
		return result.mod(this.toBN(this.mod));
	}

	mul(x: BigIntType, y: BigIntType): BigIntType {
		const result = this.toBN(x).mul(this.toBN(y));
		return result.mod(this.toBN(this.mod));
	}

	exp(x: BigIntType, y: BigIntType): BigIntType {
		return this.toBN(x).pow(this.toBN(y)).mod(this.toBN(this.mod));
	}

	modInverse(g: BigIntType): BigIntType {
		return this.toBN(g).invm(this.toBN(this.mod));
	}

	static isInInterval(b: BigIntType, bound: BigIntType): boolean {
		const bnB = BN.isBN(b) ? b : new BN(b.toString(16), 16);
		const bnBound = BN.isBN(bound) ? bound : new BN(bound.toString(16), 16);
		return bnB.lt(bnBound) && bnB.gte(new BN(0));
	}

	static appendBigIntToBytesSlice(commonBytes: Uint8Array, appended: BigIntType): Uint8Array {
		const appendedBytes = BN.isBN(appended) ? new Uint8Array(appended.toArray()) : new Uint8Array(appended.toByteArray());
		const resultBytes = new Uint8Array(commonBytes.length + appendedBytes.length);
		resultBytes.set(commonBytes);
		resultBytes.set(appendedBytes, commonBytes.length);
		return resultBytes;
	}
}

export default ModInt;