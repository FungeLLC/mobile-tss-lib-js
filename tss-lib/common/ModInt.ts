import { BigInteger } from 'jsbn';
import BN from 'bn.js';

type BigIntType = BigInteger | BN ;

class ModInt {
	private mod: BigIntType;

	constructor(mod: BigIntType) {
		this.mod = mod;
	}

	precomputeWindow(base: BN, windowSize: number): BN[] {
		const window: BN[] = new Array(1 << windowSize);
		const modN = this.toBN(this.mod);
		
		window[0] = new BN(1).mod(modN);
		window[1] = base.mod(modN);
		
		// Precompute successive powers
		for (let i = 2; i < (1 << windowSize); i++) {
			window[i] = window[i-1].mul(base).mod(modN);
		}
		
		return window;
	}

	expWindow(base: BN, exp: BN, windowSize: number, window: BN[] = []): BN {
		const modN = this.toBN(this.mod);

		if (exp.isZero()) return new BN(1);
		if (exp.eqn(1)) return base.mod(modN);

		const isNegative = exp.isNeg();
		const expBN = isNegative ? exp.neg() : exp;

		if (window.length === 0) {
			window = this.precomputeWindow(base, windowSize);
		}

		let result = new BN(1);
		const binaryStr = expBN.toString(2);
		const expBits = binaryStr.padStart(Math.ceil(binaryStr.length / windowSize) * windowSize, '0');

		// Process bits from right to left in window-sized chunks
		for (let i = expBits.length - windowSize; i >= 0; i -= windowSize) {
			// Get window value
			let windowValue = parseInt(expBits.slice(i, i + windowSize), 2);
			result = result.mul(window[windowValue]).mod(modN);

			// Square 'windowSize' times
			for (let j = 0; j < windowSize; j++) {
				result = result.sqr().mod(modN);
			}
		}

		return isNegative ? result.invm(modN) : result;
	}


	private toBN(value: BigIntType): BN {
		return BN.isBN(value) ? value : new BN(value.toString(16), 16);
	}

	private toBigInteger(value: BigIntType): BigInteger {
		return BN.isBN(value) ? new BigInteger(value.toString(16), 16) : new BigInteger(value.toString(16), 16);
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

	static fromByteArray(bytes: Uint8Array): BigIntType {
		return new BN(bytes);
	}

	static toByteArray(value: BigIntType): Uint8Array {

		if (value instanceof Uint8Array) {
			return value;
		}

		if (value instanceof Number) {
			value = new BN(value.toString(16), 16);
		}

		if (value instanceof BN) {
			return new Uint8Array(value.toArray());
		}

		if (value instanceof BigInteger) {
			return new Uint8Array(value.toByteArray());
		}

		throw new Error('Unsupported type');
	}

	static appendBigIntToBytesSlice(commonBytes: Uint8Array, appended: BigIntType): Uint8Array {
		const appendedBytes = BN.isBN(appended) ? new Uint8Array(appended.toArray()) : new Uint8Array(this.toByteArray(appended));
		const resultBytes = new Uint8Array(commonBytes.length + appendedBytes.length);
		resultBytes.set(commonBytes);
		resultBytes.set(appendedBytes, commonBytes.length);
		return resultBytes;
	}
}

export default ModInt;