import { BigInteger } from 'jsbn';
import BN from 'bn.js';

type BigIntType = BigInteger | BN;

interface ReductionContext {
    m: number;
    prime: any;
    [key: string]: any;
}

export class ModInt {
    private readonly modulus: BN;
    private reductionContext: BN.ReductionContext | null;

    constructor(mod: BN) {
        this.modulus = mod;
        this.reductionContext = null;
    }

    private getReductionContext(): BN.ReductionContext {
        if (!this.reductionContext) {
            this.reductionContext = BN.mont(this.modulus);
        }
        return this.reductionContext;
    }

    public reduce(x: BN): BN {
        if (x.isNeg()) {
            return x.umod(this.modulus);
        }

        const red = this.getReductionContext();
        return x.toRed(red).fromRed();
    }

    private toBN(value: BigIntType): BN {
        return BN.isBN(value) ? value : new BN(value.toString(16), 16);
    }

    add(x: BigIntType, y: BigIntType): BN {
        const xBN = this.toBN(x);
        const yBN = this.toBN(y);

        // Use reduction if both positive
        if (xBN.isNeg() || yBN.isNeg()) {
            return xBN.add(yBN).umod(this.modulus);
        }

        const red = this.getReductionContext();
        return xBN.toRed(red).redAdd(yBN.toRed(red)).fromRed();
    }

    mul(x: BigIntType, y: BigIntType): BN {
        const xBN = this.toBN(x);
        const yBN = this.toBN(y);

        // Use reduction if both positive
        if (xBN.isNeg() || yBN.isNeg()) {
            return xBN.mul(yBN).umod(this.modulus);
        }

        const red = this.getReductionContext();
        return xBN.toRed(red).redMul(yBN.toRed(red)).fromRed();
    }

    sub(x: BigIntType, y: BigIntType): BN {
        const xBN = this.toBN(x);
        const yBN = this.toBN(y);
        const result = xBN.sub(yBN);
        return result.umod(this.modulus);
    }

    div(x: BigIntType, y: BigIntType): BN {
        const xBN = this.toBN(x);
        const yBN = this.toBN(y);
        if (yBN.isZero()) {
            throw new Error('Division by zero is not allowed');
        }
        const yInv = yBN.invm(this.modulus);
        if (!yInv) throw new Error('No multiplicative inverse exists');
        const result = xBN.mul(yInv);
        return result.umod(this.modulus);
    }

    /**
     * Computes modular exponentiation (base^exponent mod N) using Montgomery reduction
     * This is the primary method that matches Go's Exp implementation
     * @param base - The base number
     * @param exponent - The exponent
     * @returns base^exponent mod N
     */
    public pow(base: BN, exponent: BN): BN {
        // Ensure base is within [0, modulus)
        base = base.umod(this.modulus);

        // Handle zero exponent
        if (exponent.isZero()) {
            return new BN(1);
        }

        // Use Montgomery reduction for efficient modular exponentiation
        const redContext = this.getReductionContext();
        const baseRed = base.toRed(redContext);
        const resultRed = baseRed.redPow(exponent);
        const result = resultRed.fromRed();

        // Ensure result is within [0, modulus)
        return result.umod(this.modulus);
    }

    /** 
     * @deprecated Use pow() instead - this method exists for backwards compatibility
     * Alias for pow() that accepts BigIntType inputs
     */
    modPow(base: BigIntType, exponent: BigIntType): BN {
        return this.pow(this.toBN(base), this.toBN(exponent));
    }

    /** 
     * @deprecated Use pow() instead - this method exists for backwards compatibility
     * Alias for pow() that matches older implementations
     */
    exp(base: BN, exponent: BN): BN {
        return this.pow(base, exponent);
    }

    modInverse(g: BigIntType): BN {
        const gBN = this.toBN(g);
        if (gBN.eq(this.modulus) || gBN.isZero()) {
            throw new Error('No modular inverse exists');
        }
        const inv = gBN.invm(this.modulus);
        if (inv === null) {
            throw new Error('No modular inverse exists');
        }
        return inv;
    }

    static isInInterval(b: BigIntType, bound: BigIntType): boolean {
        const bnB = BN.isBN(b) ? b : new BN(b.toString(16), 16);
        const bnBound = BN.isBN(bound) ? bound : new BN(bound.toString(16), 16);
        return bnB.lt(bnBound) && bnB.gte(new BN(0));
    }

    static fromByteArray(bytes: Uint8Array): BN {
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