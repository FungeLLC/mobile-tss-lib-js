import { Round3 } from '../../../ecdsa/keygen/Round3';
import { KGRound3Message } from '../../../ecdsa/keygen/KGRound3Message';
import { KGRound2Message1 } from '../../../ecdsa/keygen/KGRound2Message1';
import { KGRound2Message2 } from '../../../ecdsa/keygen/KGRound2Message2';
import { KeygenParams } from '../../../ecdsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../ecdsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../ecdsa/keygen/LocalTempData';
import { PartyID } from '../../../ecdsa/keygen/interfaces';
import { ECPoint } from '../../../crypto/ECPoint';
import { Share } from '../../../crypto/VSS';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';
import { RandomSource } from '../../../common/Types';
import { ProofFac } from '../../../crypto/FACProof';
import { PaillierProof } from '../../../crypto/Paillier';

describe('Round3 (ECDSA)', () => {
    let params: KeygenParams;
    let data: LocalPartySaveData;
    let temp: LocalTempData;
    let out: jest.Mock;
    let end: jest.Mock;
    let round3: Round3;
    let secp256k1: EC;
	let proof: PaillierProof;

    beforeEach(() => {
		secp256k1 = new EC('secp256k1');
		const mockParties = Array.from({ length: 3 }, (_, i) => ({
			index: i + 1,
			moniker: `party${i + 1}`,
			arrayIndex: i,
			keyInt: () => new BN(i + 1)
		}));

		params = new KeygenParams({
			partyCount: 3,
			threshold: 2,
			curve: {
				n: secp256k1.n as BN,
				g: secp256k1.g,
				p: secp256k1.curve.p,
				curve: secp256k1
			},
			parties: mockParties,
			partyID: () => mockParties[0],
			randomSource: { randomBytes: (size: number) => crypto.randomBytes(size) } as RandomSource,
			proofParams: { iterations: 1, hashLength: 32, primeBits: 256 }
		});

		proof = new PaillierProof([new BN(123), new BN(123), new BN(123), new BN(123), new BN(123)]);

        data = new LocalPartySaveData(params.partyCount());
        temp = new LocalTempData(params.partyCount());
        out = jest.fn();
        end = jest.fn();
        round3 = new Round3(params, data, temp, out, end);
    });

    describe('Initialization', () => {
        test('should initialize with round number 3', () => {
            expect(round3.number).toBe(3);
        });

        test('should not proceed without Round2 data', () => {
            expect(round3.canProceed()).toBe(false);
        });

        test('should not allow double start', async () => {
            await round3.start();
            const error = await round3.start();
            expect(error?.message).toBe('round already started');
        });
    });

    describe('Share Combination', () => {
        beforeEach(() => {
            // Setup Round2 state
            temp.shares = Array(params.totalParties).fill(null).map((_, i) => 
                new Share(2, new BN(i + 1), new BN(123))
            );
			const to = { index: 1, arrayIndex: 0 } as PartyID;
			const from = { index: 1, arrayIndex: 0 } as PartyID;
			const proof = ProofFac.fromEcdsaParams(new BN(123), new BN(123), new BN(123), new BN(123), new BN(123));

            temp.kgRound2Message1s = temp.shares.map((share) => 
                new KGRound2Message1(to, from, share.share, proof)
            );
            temp.kgRound2Message2s = temp.shares.map(() => new KGRound2Message2(
                { index: 1, arrayIndex: 0 } as PartyID,
                [],
            ));
        });

        test('should combine shares correctly', async () => {
            await round3.start();
            expect(data.xi).toBeDefined();

			if(!data.xi || !secp256k1.n) {
				throw new Error('data.xi or secp256k1.n is undefined');
			}

            expect(data.xi.lt(secp256k1.n)).toBe(true);
        });

        test('should set public key point', async () => {
            const G = secp256k1.g;
            temp.vs = [new ECPoint(secp256k1, G.getX(), G.getY())];
            await round3.start();
            expect(data.ecdsaPub).toBeDefined();
        });
    });

    describe('Message Handling', () => {
        beforeEach(async () => {
            // Setup required state
            temp.shares = [new Share(2, new BN(1), new BN(123))];
            const to = { index: 1, arrayIndex: 0 } as PartyID;
            const from = { index: 1, arrayIndex: 0 } as PartyID;
            const Facproof = ProofFac.fromEcdsaParams(new BN(123), new BN(123), new BN(123), new BN(123), new BN(123));
           	proof = new PaillierProof([new BN(123), new BN(123), new BN(123), new BN(123), new BN(123)]);
            temp.vs = [new ECPoint(secp256k1, secp256k1.g.getX(), secp256k1.g.getY())];
            await round3.start();
        });

        test('should handle valid message', () => {
            const msg = new KGRound3Message(
                { index: 2, arrayIndex: 1, moniker: 'party2' } as PartyID,
				proof
            );
            const [ok, err] = round3.update(msg);
            expect(ok).toBe(true);
            expect(err).toBeNull();
        });

        test('should reject duplicate message', () => {
            const msg = new KGRound3Message(
                { index: 2, arrayIndex: 1, moniker: 'party2' } as PartyID,
				proof
            );
            round3.update(msg);
            const [ok, err] = round3.update(msg);
            expect(ok).toBe(false);
            expect(err?.message).toContain('duplicate');
        });

        test('should reject invalid party index', () => {
            const msg = new KGRound3Message(
                { index: 99, arrayIndex: 98, moniker: 'invalid' } as PartyID,
				proof
            );
            const [ok, err] = round3.update(msg);
            expect(ok).toBe(false);
            expect(err?.message).toContain('invalid party array index');
        });

    });

    describe('Completion', () => {
        beforeEach(async () => {
            // Setup required state
           	proof = new PaillierProof([new BN(123), new BN(123), new BN(123), new BN(123), new BN(123)]);

        });

        test('should complete when all messages received (ecdsa)', async () => {
            // Setup state
            temp.shares = Array(params.totalParties).fill(null).map((_, i) => 
                new Share(2, new BN(i + 1), new BN(123))
            );
            const to = { index: 1, arrayIndex: 0 } as PartyID;
            const from = { index: 1, arrayIndex: 0 } as PartyID;
            const proofFac = ProofFac.fromEcdsaParams(new BN(123), new BN(123), new BN(123), new BN(123), new BN(123));
            temp.kgRound2Message1s = temp.shares.map(share => 
				new KGRound2Message1(to, from, share.share, proofFac)
            );
            temp.vs = [new ECPoint(secp256k1, secp256k1.g.getX(), secp256k1.g.getY())];
            
            const r3Result = await round3.start();
            expect(r3Result).toBeNull();

            // Send messages from all other parties
            for (let i = 1; i < params.totalParties; i++) {
                const msg = new KGRound3Message({
                    index: i + 1,
                    arrayIndex: i,
                    moniker: `party${i + 1}`
                } as PartyID,
				proof);
                const [ok, err] = round3.update(msg);
                expect(err).toBeNull();

                expect(ok).toBe(true);
            }

            expect(round3.isComplete()).toBe(true);
            expect(data.ecdsaPub).toBeDefined();
            expect(end).toHaveBeenCalled();
        });
    });
});