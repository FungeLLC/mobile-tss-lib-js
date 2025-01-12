import { Round1, Round2, Round3, Round4 } from '../../../ecdsa/keygen/Rounds';
import { KeygenParams } from '../../../ecdsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../ecdsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../ecdsa/keygen/LocalTempData';
import { PartyID } from '../../../ecdsa/keygen/interfaces';
import { ECPoint } from '../../../crypto/ECPoint';
import { Share } from '../../../crypto/VSS';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';
const { getRandomBytes } = require('../../../common/random');

import { HashCommitment } from '../../../crypto/Commitment';
import { ProofFac } from '../../../crypto/FACProof';
import { KGRound2Message1 } from '../../../ecdsa/keygen/KGRound2Message1';
import { KGRound2Message2 } from '../../../ecdsa/keygen/KGRound2Message2';

describe('ECDSA Keygen Integration (Realistic Data)', () => {
	const partyCount = 3;
	const threshold = 2;
	let params: KeygenParams;
	let data: LocalPartySaveData;
	let temp: LocalTempData;
	let outFn: jest.Mock;
	let endFn: jest.Mock;

	beforeEach(() => {
		const mockParties = Array.from({ length: partyCount }, (_, i) => ({
			index: i + 1,
			moniker: `party${i + 1}`,
			arrayIndex: i,
			keyInt: () => new BN(i + 1),
			toString: () => `party${i + 1}`
		}));

		const secp256k1 = new EC('secp256k1');
		const randomSource = { randomBytes: getRandomBytes };

		params = new KeygenParams({

			partyCount,

			threshold,

			curve: {

				n: secp256k1.n as BN,

				g: secp256k1.g,

				p: secp256k1.curve.p,

				curve: secp256k1

			},

			parties: mockParties,

			partyID: () => mockParties[0],

			randomSource,

			proofParams: {

				iterations: 1,

				hashLength: 32,

				primeBits: 256

			}

		});

		data = new LocalPartySaveData(partyCount);
		temp = new LocalTempData(partyCount);
		outFn = jest.fn();
		endFn = jest.fn();
	});

	function generateRandomInt(n: BN): BN {
		const bytes = crypto.randomBytes(32);
		return new BN(bytes).umod(n);
	}

	// Sample polynomial creation for VSS
	function samplePolynomial(t: number, secret: BN, q: BN): BN[] {
		const poly = new Array(t + 1);
		poly[0] = secret;
		for (let i = 1; i <= t; i++) {
			poly[i] = generateRandomInt(q);
		}
		return poly;
	}

	// Generate shares for each participant using polynomial
	function generateShares(poly: BN[], n: number, q: BN): Share[] {
		const shares = new Array<Share>(n);
		for (let i = 0; i < n; i++) {
			const x = new BN(i + 1);
			let y = new BN(0);
			for (let j = 0; j < poly.length; j++) {
				const term = x.pow(new BN(j)).mul(poly[j]).umod(q);
				y = y.add(term).umod(q);
			}
			shares[i] = new Share(poly.length - 1, x, y);
		}
		return shares;
	}

	// Generate ECDSA-based FAC Proof
	function generateFacProof(share: Share, ec: EC): ProofFac {

		const { g, n } = ec;

		if(!g) throw new Error('Elliptic curve must have a generator point');
		if(!n) throw new Error('Elliptic curve must have a prime order');


		const G = new ECPoint(ec, g.getX(), g.getY());

		const rand = generateRandomInt(n);

		const A = G.mul(rand);

		const challengeInput = Buffer.concat([

			share.id.toBuffer('be', 32),

			share.share.toBuffer('be', 32),

			A.X().toBuffer('be', 32),

			A.Y().toBuffer('be', 32)

		]);

		const challenge = crypto.createHash('sha256').update(challengeInput).digest();

		const c = new BN(challenge).umod(n);

		const z = rand.add(c.mul(share.share)).umod(n);

		const xPoint = G.mul(share.id);

		return new ProofFac(

			A.X(),

			A.Y(),

			xPoint.X(),

			xPoint.Y(),

			share.share,

			z,

			share.id,

			share.share,

			rand,

			c,

			z

		);

	}

	// Round1 test: generate VSS polynomial & shares accurately
	describe('Round1', () => {
		it('should handle full Round1 with real data', async () => {
			// Generate a random secret
			const ui = generateRandomInt(params.ec.n);
			temp.ui = ui;

			// Build polynomial with threshold, then distribute shares
			const polynomial = samplePolynomial(threshold, ui, params.ec.n);
			const shares = generateShares(polynomial, partyCount, params.ec.n);
			temp.shares = shares;

			// Generate commitments for each polynomial coefficient
			const G = new ECPoint(params.ec, params.ec.g.getX(), params.ec.g.getY());
			const vs = polynomial.map(coeff => G.mul(coeff));
			temp.vs = vs;

			// Create a hash commitment for all commitment points
			const flatPoints = vs.flatMap(point => [point.X(), point.Y()]);
			const commit = HashCommitment.new(...flatPoints);
			temp.deCommitPolyG = commit.D;

			const round1 = new Round1(params, data, temp, outFn, endFn);
			expect(await round1.start()).toBeNull();
			expect(round1.canProceed()).toBe(false);

			// Simulate receiving Round1 messages from the other parties
			for (let i = 1; i < partyCount; i++) {
				const msg = {
					getFrom: () => params.parties[i],
					content: () => ({ commitment: Buffer.alloc(32, i) }),
					isBroadcast: true,
					wireBytes: Buffer.alloc(0)
				};
				const [ok, err] = round1.update(msg);
				expect(ok).toBe(true);
				expect(err).toBeNull();
			}

			// Round1 should now be ready to proceed
			expect(round1.canProceed()).toBe(true);
		});
	});

	// Round2 test: finalize share distribution, broadcast commitments
	describe('Round2', () => {
		it('should handle Round2 with real data', async () => {
			// Recreate Round1's realistic scenario
			const ui = generateRandomInt(params.ec.n);
			const polynomial = samplePolynomial(threshold, ui, params.ec.n);
			const shares = generateShares(polynomial, partyCount, params.ec.n);
			const G = new ECPoint(params.ec, params.ec.g.getX(), params.ec.g.getY());
			const vs = polynomial.map(coeff => G.mul(coeff));

			temp.ui = ui;
			temp.shares = shares;
			temp.vs = vs;
			temp.deCommitPolyG = HashCommitment.new(...vs.flatMap(p => [p.X(), p.Y()])).D;

			// Initialize Round1
			const round1 = new Round1(params, data, temp, outFn, endFn);
			await round1.start();
			for (let i = 1; i < partyCount; i++) {
				const msg = {
					getFrom: () => params.parties[i],
					content: () => ({ commitment: Buffer.alloc(32, 1) }),
					isBroadcast: true,
					wireBytes: Buffer.alloc(0)
				};
				round1.update(msg);
			}
			expect(round1.canProceed()).toBe(true);

			// Start Round2
			const round2 = new Round2(params, data, temp, outFn, endFn);
			await round2.start();

			// Simulate receiving Round2 messages from each party
			// Each party gets a share and a FAC proof
			for (let i = 0; i < partyCount; i++) {
				const r2Msg1 = new KGRound2Message1(
					params.parties[0],
					params.parties[i],

					shares[i].share,
					generateFacProof(shares[i], params.ec)
				);
				const [ok1, err1] = round2.update(r2Msg1);
				expect(err1).toBeNull();
				expect(ok1).toBe(true);

				const r2Msg2 = new KGRound2Message2(
					params.parties[i],
					{ deCommitPolyG: vs.map(point => point.X()) }
				);
				const [ok2, err2] = round2.update(r2Msg2);
				expect(err2).toBeNull();

				expect(ok2).toBe(true);
			}

			// Round2 should be ready to proceed if we have all shares & commits
			expect(round2.canProceed()).toBe(true);
		});
	});

	// Round3 test: reconstruct the private share and set ecdsaPub
	describe('Round3', () => {
		it('should handle Round3 with realistic data', async () => {
			// Setup Round1 & Round2 data
			const ui = generateRandomInt(params.ec.n);
			const polynomial = samplePolynomial(threshold, ui, params.ec.n);
			const shares = generateShares(polynomial, partyCount, params.ec.n);
			const G = new ECPoint(params.ec, params.ec.g.getX(), params.ec.g.getY());
			const vs = polynomial.map(coeff => G.mul(coeff));

			temp.ui = ui;
			temp.shares = shares;
			temp.vs = vs;
			temp.deCommitPolyG = HashCommitment.new(...vs.flatMap(p => [p.X(), p.Y()])).D;

			// Assume Round2 has completed successfully
			temp.kgRound2Message1s = shares.map((sh, i) =>
				new KGRound2Message1(
					params.parties[i],
					params.parties[0],
					sh.share,
					generateFacProof(sh, params.ec)
				)
			);
			temp.kgRound2Message2s = shares.map((_, i) =>
				new KGRound2Message2(params.parties[i], {
					deCommitPolyG: vs.map(p => p.X())
				})
			);

			// Start Round3
			const round3 = new Round3(params, data, temp, outFn, endFn);
			expect(await round3.start()).toBeNull();

			// Feed each party's round3 msg
			for (let i = 1; i < partyCount; i++) {
				const msg = {
					getFrom: () => params.parties[i],
					content: () => ({}),
					isBroadcast: true,
					wireBytes: Buffer.from([])
				};
				const [ok, err] = round3.update(msg);
				expect(err).toBeNull();
				expect(ok).toBe(true);
			}
			expect(data.xi).toBeDefined();
			expect(data.ecdsaPub).toBeDefined();
			expect(round3.isComplete()).toBe(true);
		});
	});

	// Round4 test: verify final key correctness
	describe('Round4', () => {
		it('should finalize ECDSA Keygen', async () => {
			// Suppose in Round3 we've computed a valid private key
			data.xi = new BN(42);
			const ecInstance = new EC('secp256k1');
			const G = new ECPoint(ecInstance, ecInstance.curve.g.getX(), ecInstance.curve.g.getY());
			data.ecdsaPub = G.mul(data.xi);

			const round4 = new Round4(params, data, temp, outFn, endFn);
			expect(await round4.start()).toBeNull();
			expect(endFn).toHaveBeenCalled();

			// Validate that the public key matches data.xi
			const computed = G.mul(data.xi);
			expect(data.ecdsaPub.equals(computed)).toBe(true);
		});
	});
});