import { Round1, Round2, Round3, Round4 } from '../../../eddsa/keygen/Rounds';
import { KeygenParams } from '../../../eddsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../eddsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../eddsa/keygen/LocalTempData';
import { PartyID } from '../../../eddsa/keygen/interfaces';
import { ECPoint } from '../../../crypto/ECPoint';
import { Share } from '../../../crypto/VSS';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
const { getRandomBytes } = require('../../../common/random');
import crypto from 'crypto';
import { HashCommitment } from '../../../crypto/Commitment';
import { ProofFac } from '../../../crypto/FACProof';
import { KGRound2Message1 } from '../../../eddsa/keygen/KGRound2Message1';
import { KGRound2Message2 } from '../../../eddsa/keygen/KGRound2Message2';

describe('EdDSA Keygen Integration', () => {
	const partyCount = 3;
	const threshold = 2;
	let params: KeygenParams;
	let data: LocalPartySaveData;
	let temp: LocalTempData;
	let outFn: jest.Mock;
	let endFn: jest.Mock;

	// Helper functions
	function generateRandomInt(n: BN): BN {
		const bytes = crypto.randomBytes(32);
		return new BN(bytes).umod(n);
	}

	function samplePolynomial(t: number, secret: BN, q: BN): BN[] {
		const poly = new Array(t + 1);
		poly[0] = secret;
		for (let i = 1; i <= t; i++) {
			poly[i] = generateRandomInt(q);
		}
		return poly;
	}

	function generateShares(poly: BN[], n: number, q: BN): Share[] {
		const shares = new Array(n);
		for (let i = 0; i < n; i++) {
			const x = new BN(i + 1);
			let y = new BN(0);
			for (let j = 0; j < poly.length; j++) {
				const term = x.pow(new BN(j)).mul(poly[j]);
				y = y.add(term).umod(q);
			}
			shares[i] = new Share(poly.length - 1, x, y);
		}
		return shares;
	}

	function generateVSSCommitments(poly: BN[], g: ECPoint): ECPoint[] {
		return poly.map(coeff => g.mul(coeff));
	}

	function generateFacProof(share: Share, ec: EC): ProofFac {
		// Get curve parameters
		const { g, n } = ec.curve;
		const basePoint = new ECPoint(ec.curve, g.getX(), g.getY());
		
		// Share coordinates
		const x = share.id;
		const y = share.share;
		
		// Generate random values for proof
		const r = generateRandomInt(n);
		
		// Calculate commitment values
		const A = basePoint.mul(r);
		const yPoint = basePoint.mul(y);
		const xPoint = basePoint.mul(x);
		
		// Generate challenge hash
		const challengeInput = Buffer.concat([
			x.toBuffer('be', 32),
			y.toBuffer('be', 32),
			A.X().toBuffer('be', 32),
			A.Y().toBuffer('be', 32)
		]);
		const challenge = crypto.createHash('sha256').update(challengeInput).digest();
		const c = new BN(challenge).umod(n);
		
		// Calculate proof response values
		const z = r.add(c.mul(y)).umod(n);
		
		// Create ProofFac with actual values
		return new ProofFac(
			A.X(),           // P - commitment X coordinate
			A.Y(),           // Q - commitment Y coordinate
			xPoint.X(),      // A.X - x commitment X coordinate  
			xPoint.Y(),      // A.Y - x commitment Y coordinate
			y,               // t - shared secret
			z,               // sigma - proof response
			x,               // z1 - x coordinate
			y,               // z2 - y coordinate
			r,               // w1 - randomness
			c,               // w2 - challenge
			z                // v - response
		);
	}


	beforeEach(() => {
		const mockParties = Array.from({ length: partyCount }, (_, i) => ({
			index: i + 1,
			arrayIndex: i,
			keyInt: () => new BN(i + 1),
			toString: () => `party${i + 1}`,
			moniker: `party${i + 1}`
		}));

		const randomSource = { randomBytes: getRandomBytes };
		params = new KeygenParams({
			partyCount,
			threshold,
			curve: {
				// Ed25519 curve order (l)
				n: new BN('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 16),
				// Base point
				g: new EC('ed25519').g,
				// Ed25519 prime (p)
				p: new BN('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', 16),
				curve: new EC('ed25519')
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

	describe('Round1', () => {
		test('should handle full round1 flow', async () => {
			// Generate random secret ui
			const ui = generateRandomInt(params.ec.n);
			temp.ui = ui;

			// Generate polynomial and shares
			const polynomial = samplePolynomial(threshold, ui, params.ec.n);
			const shares = generateShares(polynomial, partyCount, params.ec.n);
			temp.shares = shares;

			// Generate VSS commitments
			const basePoint = new ECPoint(params.ec.curve, params.ec.g.getX(), params.ec.g.getY());
			console.log('basePoint type:', typeof basePoint);
			console.log('basePoint structure:', basePoint);
			const vs = generateVSSCommitments(polynomial, basePoint);
			temp.vs = vs;

			// Generate commitment decommitment pair
			const flatPoints = vs.reduce((acc: BN[], point: ECPoint) => [...acc, point.X(), point.Y()], []);
			const commitment = HashCommitment.new(...flatPoints);
			temp.deCommitPolyG = commitment.D;



			// Rest of test...
			const round1 = new Round1(params, data, temp, outFn, endFn);
			expect(await round1.start()).toBeNull();
			expect(round1.canProceed()).toBe(false);

			// Verify initial state
			expect(temp.ui).toBeDefined();
			expect(temp.shares).toBeDefined();
			expect(temp.vs).toBeDefined();
			expect(temp.deCommitPolyG).toBeDefined();

			// Process messages from other parties
			for (let i = 1; i < partyCount; i++) {
				const msg = {

					getFrom: () => ({ index: i + 1, arrayIndex: i, moniker: `party${i + 1}` } as PartyID), // Mock party ID

					content: () => ({

						commitment: Buffer.from([1, 2, 3])

					}),

					isBroadcast: false,

					wireBytes: Buffer.alloc(0)

				};

				const [ok, err] = round1.update(msg);
				expect(ok).toBe(true);
				expect(err).toBeNull();
			}

			// Verify round completion
			expect(round1.canProceed()).toBe(true);
		});
	});

	describe('Round2', () => {
		test('should handle full round2 flow', async () => {
			// Generate polynomial and shares
			const ui = generateRandomInt(params.ec.n);
			const polynomial = samplePolynomial(threshold, ui, params.ec.n);
			const shares = generateShares(polynomial, partyCount, params.ec.n);
			const basePoint = new ECPoint(params.ec.curve, params.ec.g.getX(), params.ec.g.getY());
			const vs = generateVSSCommitments(polynomial, basePoint);

			// Setup Round1 state
			temp.ui = ui;
			temp.shares = shares;
			temp.vs = vs;
			temp.deCommitPolyG = HashCommitment.new(...ECPoint.flattenECPoints(vs)).D;

			const round1 = new Round1(params, data, temp, outFn, endFn);
			await round1.start();

			const round2 = new Round2(params, data, temp, outFn, endFn);
			expect(round2.canProceed()).toBe(false);
			round2.start();
			// Initialize message arrays
			temp.kgRound2Message1s = [];
			temp.kgRound2Message2s = [];

			// Process Round2 messages
			for (let i = 0; i < partyCount; i++) {
				const kgRoundMsg = new KGRound2Message1({
					index: i + 1,
					arrayIndex: i,
					moniker: `party${i + 1}`
				} as PartyID, 
				{ index: i + 1, arrayIndex: i, moniker: `party${i + 1}` } as PartyID,
				shares[i].share,
				generateFacProof(shares[i], params.ec),
			);

				const [ok1, err1] = round2.update(kgRoundMsg);
				expect(err1).toBeNull();

				expect(ok1).toBe(true);


				const kgRound2Message2 = new KGRound2Message2(
					{ index: i + 1, arrayIndex: i, moniker: `party${i + 1}` } as PartyID,

					{ deCommitPolyG: vs.map(p => p.X()) }
				);

				const [ok2, err2] = round2.update(kgRound2Message2);
				expect(err2).toBeNull();

				expect(ok2).toBe(true);
			}

			expect(round2.canProceed()).toBe(true);
		});
	});

	describe('Round3', () => {
		test('should handle full round3 flow', async () => {
			// Setup Round1+2 state with real values
			const ui = generateRandomInt(params.ec.n);
			const polynomial = samplePolynomial(threshold, ui, params.ec.n);
			const shares = generateShares(polynomial, partyCount, params.ec.n);
			const basePoint = new ECPoint(params.ec.curve, params.ec.g.getX(), params.ec.g.getY());
			const vs = generateVSSCommitments(polynomial, basePoint);
			
			// Set temporary data
			temp.ui = ui;
			temp.shares = shares;
			temp.vs = vs;
			temp.deCommitPolyG = HashCommitment.new(...ECPoint.flattenECPoints(vs)).D;
			
			// Setup Round2 messages with proper message objects
			temp.kgRound2Message1s = shares.map((share, i) =>
				new KGRound2Message1(
					{ index: i + 1, arrayIndex: i, moniker: `party${i + 1}` } as PartyID,
					{ index: 1, arrayIndex: 0, moniker: 'party1' } as PartyID,
					share.share,
					generateFacProof(share, params.ec)
				)
			);

			temp.kgRound2Message2s = shares.map((_, i) =>
				new KGRound2Message2(
					{ index: i + 1, arrayIndex: i, moniker: `party${i + 1}` } as PartyID,
					{
						deCommitPolyG: vs.map(p => p.X())
					}
				)
			);

			const round3 = new Round3(params, data, temp, outFn, endFn);
			await round3.start();

			// Process Round3 messages with real values
			for (let i = 0; i < partyCount; i++) {
				const msg = {
					getFrom: () => ({ 
						index: i + 1, 
						arrayIndex: i, 
						moniker: `party${i + 1}` 
					} as PartyID),
					content: () => ({
						xi: shares[i].share,
						vssVerification: true
					}),
					isBroadcast: true,
					wireBytes: Buffer.from([])
				};
				const [ok, err] = round3.update(msg);
				expect(ok).toBe(true);
				expect(err).toBeNull();
			}

			expect(round3.isComplete()).toBe(true);
			expect(data.eddsaPub).toBeDefined();
		});
	});

	describe('Round4', () => {
		test('should complete keygen process', async () => {
			// Setup final state with real values
			const ui = generateRandomInt(params.ec.n);
			const polynomial = samplePolynomial(threshold, ui, params.ec.n);
			const basePoint = new ECPoint(params.ec.curve, params.ec.g.getX(), params.ec.g.getY());
			const vs = generateVSSCommitments(polynomial, basePoint);
			
			// Set final data state
			data.xi = ui;
			data.eddsaPub = vs[0]; // Public key is first VSS commitment
			
			const round4 = new Round4(params, data, temp, outFn, endFn);
			expect(await round4.start()).toBeNull();
			expect(endFn).toHaveBeenCalled();
			
			// Verify final public key
			const computedPub = basePoint.mul(ui);
			expect(data.eddsaPub.equals(computedPub)).toBe(true);
		});
	});
});