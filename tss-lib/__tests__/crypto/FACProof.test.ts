import BN from 'bn.js';
import { ProofFac } from '../../crypto/FACProof';
import { ec as EC } from 'elliptic';
import { getRandomPrimeInt } from '../../common/Random'; // Suppose we have a function that matches Go's GetRandomPrimeInt
import { GenerateNTildei } from '../../crypto/utils' // Suppose we have a function that matches Go's GenerateNTildei
import { expect } from '@jest/globals';
import { getRandomBytes } from '../../common/Random';


describe('FACProof', () => {
	const testSafePrimeBits = 256;
	const Session = Buffer.from('session');
	let ec: EC;

	beforeAll(() => {
		ec = new EC('secp256k1');
	});

	it('should replicate Go proof generation and verification', () => {
		console.log("Test Safe Prime Bits:",testSafePrimeBits);
		// Generate N0p, N0q
		const N0p = getRandomPrimeInt(testSafePrimeBits);
		console.log("N0p:",N0p);
		const N0q = getRandomPrimeInt(testSafePrimeBits);
		console.log("N0q:",N0q);
		const N0 = N0p.mul(N0q);
		console.log("N0:",N0);

		// Generate NCap, s, t
        const randomFunc = () => getRandomBytes(testSafePrimeBits / 8);

        const [NCap, s, t] = GenerateNTildei(randomFunc, [getRandomPrimeInt(testSafePrimeBits), getRandomPrimeInt(testSafePrimeBits)]);

		console.log("NCap:",NCap);


        // Create new proof

        const proof = ProofFac.newProof(

            Session,

            ec,

            N0,

            NCap,

            s,

            t,

            N0p,

            N0q

        );

		console.log("Proof:",proof);

		// Verify
		const ok = proof.verify(Session, ec, N0, NCap, s, t);
		expect(ok).toBe(true);

		// Repeat test with new primes
		const N0p2 = getRandomPrimeInt(testSafePrimeBits);
		const N0q2 = getRandomPrimeInt(testSafePrimeBits);
		const N02 = N0p2.mul(N0q2);

		const proof2 = ProofFac.newProof(
			Session,
			ec,
			N02,
			NCap,
			s,
			t,
			N0p2,
			N0q2
		);
		const ok2 = proof2.verify(Session, ec, N02, NCap, s, t);
		expect(ok2).toBe(true);
	});
});