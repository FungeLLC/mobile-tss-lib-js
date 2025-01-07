import ModInt from '../../common/ModInt';
import BN from 'bn.js';

describe('ModInt Exponentiation', () => {
	let modInt: ModInt;
	const modulus = new BN(23); // Small prime for testing

	beforeEach(() => {
		modInt = new ModInt(modulus);
	});

	describe('exp method', () => {
		it('computes 2^5 mod 23 correctly', () => {
			const base = new BN(2);
			const exp = new BN(5);
			const expected = new BN(9); // 2^5 = 32; 32 mod 23 = 9
			expect(modInt.exp(base, exp).eq(expected)).toBe(true);
		});

		it('handles exponent 0', () => {
			const base = new BN(5);
			const exp = new BN(0);
			const expected = new BN(1);
			expect(modInt.exp(base, exp).eq(expected)).toBe(true);
		});

		it('handles exponent 1', () => {
			const base = new BN(7);
			const exp = new BN(1);
			expect(modInt.exp(base, exp).eq(base)).toBe(true);
		});

		it('handles large numbers', () => {
			const base = new BN('123456789', 16);
			const exp = new BN('FEDCBA', 16);
			const result = modInt.exp(base, exp);
			expect(result.lt(modulus)).toBe(true);
		});
	});

	describe('modPow method', () => {
		it('computes 2^5 mod 23 correctly', () => {
			const base = new BN(2);
			const exp = new BN(5);
			const expected = new BN(9);
			const result = modInt.modPow(base, exp) as BN;
			expect(result.eq(expected)).toBe(true);
		});

		it('matches exp method results', () => {
			const base = new BN(3);
			const exp = new BN(7);
			const expResult = modInt.exp(base, exp);
			const modPowResult = modInt.modPow(base, exp) as BN;
			expect(modPowResult.eq(expResult)).toBe(true);
		});

		it('handles large modulus', () => {
			const largeModulus = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
			const largeModInt = new ModInt(largeModulus);
			const base = new BN('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16);
			const exp = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
			const result = largeModInt.modPow(base, exp) as BN;
			expect(result.lt(largeModulus)).toBe(true);
		});

		it('computes small exponents correctly', () => {
			const modulus = new BN(23);
			const modInt = new ModInt(modulus);
			const base = new BN(5);
			const exponent = new BN(3);
			const expected = new BN(10); // 5^3 = 125; 125 mod 23 = 10
			const result = modInt.modPow(base, exponent);
			expect(result.eq(expected)).toBe(true);
		});

		it('computes large exponents correctly', () => {
			const modulus = new BN('A7F3B', 16); // 688955 in decimal
			const modInt = new ModInt(modulus);
			const base = new BN('12345', 16); // 74565 in decimal
			const exponent = new BN('FEDCBA', 16); // 16702650 in decimal
			const expected = modInt.exp(base, exponent);
			const result = modInt.modPow(base, exponent);
			expect(result).toEqual(expected);
		});
	});

	describe('ModInt.pow', () => {
		it('should handle potential overflows correctly', () => {
			const modulus = new BN(17); // Small prime for testing
			const modInt = new ModInt(modulus);
			const base = new BN('FFFFFFFFFFFFFFFF', 16); // Very large number
			const exp = new BN('FFFFFFFFFFFFFFFF', 16); // Very large exponent
			
			const result = modInt.pow(base, exp);
			
			expect(result.lt(modulus)).toBe(true);
			expect(result.gte(new BN(0))).toBe(true);
			
			// Verify that taking the result to power 2 still works
			const doubleResult = modInt.pow(result, new BN(2));
			expect(doubleResult.lt(modulus)).toBe(true);
		});
		it('should handle small numbers with different bases and exponents', () => {
			const modulus = new BN(11); // Small prime
			const modInt = new ModInt(modulus);
			const testCases = [
			{ base: 2, exp: 3 },     // 2^3
			{ base: 3, exp: 2 },     // 3^2
			{ base: 4, exp: 3 },     // 4^3
			{ base: 5, exp: 2 },     // 5^2
			{ base: 6, exp: 4 },     // 6^4
			];

			testCases.forEach(({ base, exp }) => {
			const expected = new BN(
				(BigInt(Math.pow(base, exp)) % 11n).toString()
			);
			const result = modInt.pow(new BN(base), new BN(exp));
			expect(result.eq(expected)).toBe(true);
			});
		});
		

		it('should correctly compute large modular exponentiation', () => {
			const modulus = new BN('ABCDEF0123456789', 16);
			const modInt = new ModInt(modulus);
			const base = new BN('9876543210FEDCBA', 16);
			const exponent = new BN('123456789ABCDEF0', 16);
			

			const expected = base.toRed(BN.red(modulus)).redPow(exponent).fromRed();

			const result = modInt.pow(base, exponent);

			console.log('expected/result', expected, result);
			
			expect(result.eq(expected)).toBe(true);
			
			// Additional validations
			expect(result.lt(modulus)).toBe(true); // Result must be less than modulus
			expect(result.gte(new BN(0))).toBe(true); // Result must be non-negative
			
			// Test algorithm properties
			// Test that (x^a)^1 === x^a
			const powerOfOne = modInt.pow(result, new BN(1));
			expect(powerOfOne.eq(result)).toBe(true);
			
			// Test that x^0 === 1
			const powerOfZero = modInt.pow(base, new BN(0)); 
			expect(powerOfZero.eq(new BN(1))).toBe(true);
		});
	

		it('should return 1 when exponent is zero', () => {
			const modulus = new BN('1234567890ABCDEF', 16);
			const modInt = new ModInt(modulus);

			const base = new BN('FEDCBA9876543210', 16);
			const exponent = new BN(0);

			const result = modInt.pow(base, exponent);

			expect(result.eq(new BN(1))).toBe(true);
		});
	});
	describe('mul method', () => {
		it('computes 2 * 5 mod 23 correctly', () => {
			const a = new BN(2);
			const b = new BN(5);
			const expected = new BN(10); // 2 * 5 = 10; 10 mod 23 = 10
			expect(modInt.mul(a, b).eq(expected)).toBe(true);
		});

		it('computes 7 * 4 mod 23 correctly', () => {
			const a = new BN(7);
			const b = new BN(4);
			const expected = new BN(5); // 7 * 4 = 28; 28 mod 23 = 5
			expect(modInt.mul(a, b).eq(expected)).toBe(true);
		});

		it('handles multiplication by zero', () => {
			const a = new BN(0);
			const b = new BN(15);
			const expected = new BN(0);
			expect(modInt.mul(a, b).eq(expected)).toBe(true);
		});

		it('handles multiplication resulting in modulus', () => {
			const a = new BN(23);
			const b = new BN(1);
			const expected = new BN(0); // 23 * 1 = 23; 23 mod 23 = 0
			expect(modInt.mul(a, b).eq(expected)).toBe(true);
		});

		it('handles large numbers', () => {
			const a = new BN('123456789ABCDEF', 16);
			const b = new BN('FEDCBA987654321', 16);
			const result = modInt.mul(a, b);
			expect(result.lt(modulus)).toBe(true);
		});

		it('handles negative numbers', () => {
			const a = new BN(-2);
			const b = new BN(5);
			const expected = modulus.sub(new BN(10)); // -2 * 5 = -10; -10 mod 23 = 13
			expect(modInt.mul(a, b).eq(expected)).toBe(true);
		});

		it('computes multiplication of negative operands', () => {
			const a = new BN(-3);
			const b = new BN(-7);
			const expected = new BN(21); // -3 * -7 = 21; 21 mod 23 = 21
			expect(modInt.mul(a, b).eq(expected)).toBe(true);
		});

		//test for overflows
		it('should handle potential overflows correctly', () => {
			const modulus = new BN(17); // Small prime for testing
			const modInt = new ModInt(modulus);
			const a = new BN('FFFFFFFFFFFFFFFF', 16); // Very large number
			const b = new BN('FFFFFFFFFFFFFFFF', 16); // Very large number
			
			const result = modInt.mul(a, b);
			
			expect(result.lt(modulus)).toBe(true);
			expect(result.gte(new BN(0))).toBe(true);
		});
	});
	//tests for add
	describe('add method', () => {
		it('computes 2 + 5 mod 23 correctly', () => {
			const a = new BN(2);
			const b = new BN(5);
			const expected = new BN(7); // 2 + 5 = 7; 7 mod 23 = 7
			expect(modInt.add(a, b).eq(expected)).toBe(true);
		});

		it('computes 7 + 4 mod 23 correctly', () => {
			const a = new BN(7);
			const b = new BN(4);
			const expected = new BN(11); // 7 + 4 = 11; 11 mod 23 = 11
			expect(modInt.add(a, b).eq(expected)).toBe(true);
		});

		it('handles addition resulting in modulus 0', () => {
			const a = new BN(22);
			const b = new BN(1);
			const expected = new BN(0); // 22 + 1 = 23; 23 mod 23 = 0
			expect(modInt.add(a, b).eq(expected)).toBe(true);
		});
		it('handles addition resulting in modulus', () => {
			const a = new BN(23);
			const b = new BN(1);
			const expected = new BN(1); // 22 + 1 = 23; 23 mod 23 = 0
			expect(modInt.add(a, b).eq(expected)).toBe(true);
		});
		it('handles large numbers', () => {
			const a = new BN('123456789ABCDEF', 16);
			const b = new BN('FEDCBA987654321', 16);
			const result = modInt.add(a, b);
			expect(result.lt(modulus)).toBe(true);
		});

		it('handles negative numbers', () => {
			const a = new BN(-2);
			const b = new BN(5);
			const expected = new BN(3); // -2 + 5 = 3; 3 mod 23 = 3
			expect(modInt.add(a, b).eq(expected)).toBe(true);
		});

		it('computes addition of negative operands', () => {
			const a = new BN(-3);
			const b = new BN(-7);
			const expected = new BN(13); // -3 + -7 = -10; -10 mod 23 = 13

			const result = modInt.add(a, b);

			console.log('expected/result', expected, result);

			expect(result.eq(expected)).toBe(true);
		});

		//test for overflows
		it('should handle potential overflows correctly', () => {
			const modulus = new BN(17); // Small
			const modInt = new ModInt(modulus);
			const a = new BN('FFFFFFFFFFFFFFFF', 16); // Very large number
			const b = new BN('FFFFFFFFFFFFFFFF', 16); // Very large number

			const result = modInt.add(a, b) as BN;

			expect(result.lt(modulus)).toBe(true);
			expect(result.gte(new BN(0))).toBe(true);
		}
		);
	}
	);
	describe('ModInt Exponentiation', () => {
		let modInt: ModInt;
		const modulus = new BN(23); // Small prime for testing

		beforeEach(() => {
			modInt = new ModInt(modulus);
		});

		// Existing test cases...

		describe('sub method', () => {
			it('computes 5 - 2 mod 23 correctly', () => {
				const a = new BN(5);
				const b = new BN(2);
				const expected = new BN(3); // 5 - 2 = 3; 3 mod 23 = 3
				expect(modInt.sub(a, b).eq(expected)).toBe(true);
			});

			it('handles result becoming negative', () => {
				const a = new BN(2);
				const b = new BN(5);
				const expected = new BN(20); // 2 - 5 = -3; -3 mod 23 = 20
				expect(modInt.sub(a, b).eq(expected)).toBe(true);
			});

			it('computes subtraction resulting in zero', () => {
				const a = new BN(7);
				const b = new BN(7);
				const expected = new BN(0); // 7 - 7 = 0; 0 mod 23 = 0
				expect(modInt.sub(a, b).eq(expected)).toBe(true);
			});

			it('handles large numbers', () => {
				const a = new BN('123456789ABCDEF', 16);
				const b = new BN('FEDCBA987654321', 16);
				const result = modInt.sub(a, b);
				expect(result.lt(modulus)).toBe(true);
			});

			it('handles negative operands', () => {
				const a = new BN(-5);
				const b = new BN(-2);
				const expected = new BN(20); // -5 - (-2) = -3; -3 mod 23 = 20
				expect(modInt.sub(a, b).eq(expected)).toBe(true);
			});
		});

		describe('div method', () => {
			it('computes 10 / 5 mod 23 correctly', () => {
				const a = new BN(10);
				const b = new BN(5);
				const invB = b.invm(modulus);
				const expected = a.mul(invB).umod(modulus);
				expect(modInt.div(a, b).eq(expected)).toBe(true);
			});

			it('handles division by self', () => {
				const a = new BN(7);
				const expected = new BN(1); // 7 / 7 mod 23 = 1
				expect(modInt.div(a, a).eq(expected)).toBe(true);
			});

			it('handles division by 1', () => {
				const a = new BN(15);
				const b = new BN(1);
				expect(modInt.div(a, b).eq(a.umod(modulus))).toBe(true);
			});

			it('handles large numbers', () => {
				const a = new BN('123456789ABCDEF', 16);
				const b = new BN('FEDCBA987654321', 16);
				const result = modInt.div(a, b);
				expect(result.lt(modulus)).toBe(true);
			});

			it('throws error when dividing by zero', () => {
				const a = new BN(5);
				const b = new BN(0);
				expect(() => modInt.div(a, b)).toThrow();
			});
		});

		describe('modInverse method', () => {
			it('computes modular inverse correctly', () => {
				const a = new BN(3);
				const expected = a.invm(modulus);
				expect(modInt.modInverse(a).eq(expected)).toBe(true);
			});

			it('handles number with no inverse', () => {
				const a = modulus; // modulus and 0 have no inverse modulo modulus
				expect(() => modInt.modInverse(a)).toThrow();
			});

			it('handles inverse of 1', () => {
				const a = new BN(1);
				const expected = new BN(1);
				expect(modInt.modInverse(a).eq(expected)).toBe(true);
			});

			it('handles large numbers', () => {
				const a = new BN('123456789ABCDEF', 16);
				const result = modInt.modInverse(a);
				expect(result.lt(modulus)).toBe(true);
			});
		});

		describe('reduce method', () => {
			it('reduces numbers correctly', () => {
				const a = new BN(50);
				const expected = a.umod(modulus);
				expect(modInt.reduce(a).eq(expected)).toBe(true);
			});

			it('handles numbers less than modulus', () => {
				const a = new BN(15);
				expect(modInt.reduce(a).eq(a)).toBe(true);
			});

			it('handles negative numbers', () => {
				const a = new BN(-5);
				const expected = a.umod(modulus);
				expect(modInt.reduce(a).eq(expected)).toBe(true);
			});

			it('handles zero', () => {
				const a = new BN(0);
				expect(modInt.reduce(a).eq(a)).toBe(true);
			});
		});

		describe('Static methods', () => {
			describe('isInInterval', () => {
				it('returns true when number is within interval', () => {
					const b = new BN(5);
					const bound = new BN(10);
					expect(ModInt.isInInterval(b, bound)).toBe(true);
				});

				it('returns false when number equals bound', () => {
					const b = new BN(10);
					const bound = new BN(10);
					expect(ModInt.isInInterval(b, bound)).toBe(false);
				});

				it('returns false when number is negative', () => {
					const b = new BN(-1);
					const bound = new BN(10);
					expect(ModInt.isInInterval(b, bound)).toBe(false);
				});

				it('handles large numbers', () => {
					const b = new BN('FFFFFFFFFFFFFFFF', 16);
					const bound = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);
					expect(ModInt.isInInterval(b, bound)).toBe(true);
				});
			});

			describe('fromByteArray and toByteArray', () => {
				it('converts BN to byte array and back correctly', () => {
					const value = new BN('123456789ABCDEF', 16);
					const byteArray = ModInt.toByteArray(value);
					const result = ModInt.fromByteArray(byteArray);
					expect(result.eq(value)).toBe(true);
				});

				it('handles empty byte array', () => {
					const byteArray = new Uint8Array([]);
					const result = ModInt.fromByteArray(byteArray);
					expect(result.eq(new BN(0))).toBe(true);
				});

				it('handles zero', () => {
					const value = new BN(0);
					const byteArray = ModInt.toByteArray(value);
					const result = ModInt.fromByteArray(byteArray);
					expect(result.eq(value)).toBe(true);
				});

				it('throws error on unsupported type in toByteArray', () => {
					expect(() => ModInt.toByteArray(null as any)).toThrow('Unsupported type');
				});
			});

			describe('appendBigIntToBytesSlice', () => {
				it('appends BigInt to byte array correctly', () => {
					const commonBytes = new Uint8Array([1, 2, 3]);
					const appended = new BN(4);
					const expected = new Uint8Array([1, 2, 3, 4]);
					const result = ModInt.appendBigIntToBytesSlice(commonBytes, appended);
					expect(result).toEqual(expected);
				});

				it('handles empty commonBytes', () => {
					const commonBytes = new Uint8Array([]);
					const appended = new BN(255);
					const expected = new Uint8Array([255]);
					const result = ModInt.appendBigIntToBytesSlice(commonBytes, appended);
					expect(result).toEqual(expected);
				});

				it('handles large BigInt values', () => {
					const commonBytes = new Uint8Array([0xAA, 0xBB]);
					const appended = new BN('FFFFFFFFFFFFFFFF', 16);
					const appendedBytes = ModInt.toByteArray(appended);
					const expected = new Uint8Array([...commonBytes, ...appendedBytes]);
					const result = ModInt.appendBigIntToBytesSlice(commonBytes, appended);
					expect(result).toEqual(expected);
				});

				it('throws error on unsupported type', () => {
					const commonBytes = new Uint8Array([1, 2, 3]);
					expect(() => ModInt.appendBigIntToBytesSlice(commonBytes, null as any)).toThrow('Unsupported type');
				});
			});
		});
	});
});