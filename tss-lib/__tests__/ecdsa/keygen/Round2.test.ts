import { Round2 } from '../../../ecdsa/keygen/Round2';
import { KGRound2Message1 } from '../../../ecdsa/keygen/KGRound2Message1';
import { KGRound2Message2 } from '../../../ecdsa/keygen/KGRound2Message2';
import { Share } from '../../../crypto/VSS';
import { ECPoint } from '../../../crypto/ECPoint';
import { ProofFac } from '../../../crypto/FACProof';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';
import { KeygenParams } from '../../../ecdsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../ecdsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../ecdsa/keygen/LocalTempData';
import { RandomSource } from '../../../common/Types';


describe('Round2 (ECDSA)', () => {
    let params: KeygenParams;
    let data: LocalPartySaveData;
    let temp: LocalTempData;
    let out: jest.Mock;
    let end: jest.Mock;
    let round2: Round2;
    let secp256k1: EC;

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


        data = new LocalPartySaveData(params.partyCount());
        temp = new LocalTempData(params.partyCount());
        out = jest.fn();
        end = jest.fn();
        round2 = new Round2(params, data, temp, out, end);

        // Setup Round1 state
        temp.ui = new BN(crypto.randomBytes(32));
        temp.shares = Array(params.totalParties).fill(null).map((_, i) =>
            new Share(2, new BN(i + 1), new BN(crypto.randomBytes(32)))
        );
        temp.vs = Array(params.threshold + 1).fill(null).map(() => {
            const point = secp256k1.g.mul(new BN(crypto.randomBytes(32)));
            return new ECPoint(secp256k1, point.getX(), point.getY());
        });
        temp.deCommitPolyG = temp.vs.map(p => p.X());
    });

    describe('Initialization', () => {
        test('should initialize with round number 2', () => {
            expect(round2.number).toBe(2);
        });

        test('should initialize ok arrays correctly', () => {
            expect(round2['ok1'].length).toBe(params.totalParties);
            expect(round2['ok2'].length).toBe(params.totalParties);
        });
    });

    describe('Round State', () => {
        test('should not proceed without Round1 data', () => {
            expect(round2.canProceed()).toBe(false);
        });

        test('should not allow double start', async () => {
            await round2.start();
            const error = await round2.start();
            expect(error?.message).toBe('round already started');
        });
    });

    describe('Share Distribution', () => {
        test('should distribute shares with valid proofs', async () => {
            await round2.start();
            expect(out).toHaveBeenCalled();
            const msg1 = out.mock.calls[0][0];
            expect(msg1 instanceof KGRound2Message1).toBe(true);
        });

        test('should broadcast decommitment data', async () => {
            await round2.start();
            const msg2 = out.mock.calls.find(call => call[0] instanceof KGRound2Message2);
            expect(msg2).toBeDefined();
        });
    });

    describe('Message Handling', () => {
        test('should handle valid share message', async () => {
            await round2.start();
            const msg = new KGRound2Message1(
                { index: 2, arrayIndex: 1, moniker: 'party2', keyInt: () => new BN(2) },
                { index: 1, arrayIndex: 0, moniker: 'party1', keyInt: () => new BN(1) },
                new BN(123),
                ProofFac.fromEcdsaParams(
                    new BN(1), new BN(2), new BN(3), new BN(4), new BN(5)
                )
            );
            const [ok, err] = round2.update(msg);
            expect(ok).toBe(true);
            expect(err).toBeNull();
        });

        test('should handle valid decommitment message', async () => {
            await round2.start();
            const msg = new KGRound2Message2(
                { index: 2, arrayIndex: 1, moniker: 'party2', keyInt: () => new BN(2) },
                { deCommitPolyG: temp.deCommitPolyG }
            );
            const [ok, err] = round2.update(msg);
            expect(ok).toBe(true);
            expect(err).toBeNull();
        });

        test('should reject duplicate messages', async () => {
            await round2.start();
            const msg = new KGRound2Message1(
                { index: 3, arrayIndex: 2, moniker: 'party3', keyInt: () => new BN(3) },
                { index: 2, arrayIndex: 1, moniker: 'party1', keyInt: () => new BN(1) },
                new BN(123),
                ProofFac.fromEcdsaParams(
                    new BN(1), new BN(2), new BN(3), new BN(4), new BN(5)
                )
            );
            
            round2.update(msg);

            const [ok, err] = round2.update(msg);
            expect(ok).toBe(false);
            expect(err?.message).toContain('duplicate');
        });
    });

    describe('Completion', () => {
        test('should complete when all messages received', async () => {
            await round2.start();
            // Simulate receiving all required messages
            for (let i = 1; i < params.totalParties; i++) {
                round2.update(new KGRound2Message1(
                    { index: 1, arrayIndex: 0, keyInt: () => new BN(1), moniker: 'party1' },
                    { index: i + 1, arrayIndex: i, keyInt: () => new BN(i + 1) , moniker: `party${i + 1}` },
                    new BN(123),
                    ProofFac.fromEcdsaParams(
                        new BN(1), new BN(2), new BN(3), new BN(4), new BN(5)
                    )
                ));
                round2.update(new KGRound2Message2(
                    { index: i + 1, arrayIndex: i, keyInt: () => new BN(i + 1), moniker: `party${i + 1}` },
                    { deCommitPolyG: temp.deCommitPolyG }
                ));
            }
            expect(round2.canProceed()).toBe(true);
            expect(end).toHaveBeenCalled();
        });
    });
});