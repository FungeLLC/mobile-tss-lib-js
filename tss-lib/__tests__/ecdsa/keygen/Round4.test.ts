import { Round4 } from '../../../ecdsa/keygen/Round4';
import { KeygenParams } from '../../../ecdsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../ecdsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../ecdsa/keygen/LocalTempData';
import { PartyID } from '../../../ecdsa/keygen/interfaces';
import { ECPoint } from '../../../crypto/ECPoint';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';
import { RandomSource } from '../../../common/Types';
import { PaillierProof } from '../../../crypto/Paillier';

describe('Round4 (ECDSA)', () => {
    let params: KeygenParams;
    let data: LocalPartySaveData;
    let temp: LocalTempData;
    let out: jest.Mock;
    let end: jest.Mock;
    let round4: Round4;
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
        round4 = new Round4(params, data, temp, out, end);
    });

    describe('Initialization', () => {
        test('should initialize with round number 4', () => {
            expect(round4.number).toBe(4);
        });

        test('should not proceed without Round3 data', () => {
            expect(round4.canProceed()).toBe(false);
        });

        test('should not allow double start', async () => {
            await round4.start();
            const error = await round4.start();
            expect(error?.message).toBe('round already started');
        });
    });

    describe('Key Verification', () => {
        test('should fail if xi is missing', async () => {
            data.ecdsaPub = new ECPoint(secp256k1, secp256k1.g.getX(), secp256k1.g.getY());
            const error = await round4.start();
            expect(error?.message).toBe('private share (xi) is missing');
        });

        test('should fail if ecdsaPub is missing', async () => {
            data.xi = new BN(123);
            const error = await round4.start();
            expect(error?.message).toBe('ECDSA public key not set');
        });

        test('should verify key successfully', async () => {
            // Setup valid key pair
            const privateKey = new BN(123);
            const publicKey = secp256k1.g.mul(privateKey);
            data.xi = privateKey;
            data.ecdsaPub = new ECPoint(secp256k1, publicKey.getX(), publicKey.getY());

            const error = await round4.start();
            expect(error).toBeNull();
            expect(end).toHaveBeenCalled();
        });

        test('should fail if key verification fails', async () => {
            // Setup mismatched key pair
            data.xi = new BN(123);
            const wrongPubKey = secp256k1.g.mul(new BN(456));
            data.ecdsaPub = new ECPoint(secp256k1, wrongPubKey.getX(), wrongPubKey.getY());

            const error = await round4.start();
            expect(error?.message).toBe('final key verification failed');
        });
    });

    describe('Message Handling', () => {
        beforeEach(() => {
            // Setup valid state
            const privateKey = new BN(123);
            const publicKey = secp256k1.g.mul(privateKey);
            data.xi = privateKey;
            data.ecdsaPub = new ECPoint(secp256k1, publicKey.getX(), publicKey.getY());
        });

        test('should handle valid message', () => {
            const msg = {
                getFrom: () => ({ index: 2, arrayIndex: 1, moniker: 'party2', keyInt: () => new BN(2) }),
                content: () => ({}),
                isBroadcast: true,
                wireBytes: Buffer.from([])
            };
            const [ok, err] = round4.update(msg);
            expect(err).toBeNull();

            expect(ok).toBe(true);
        });

        test('should reject invalid party index', () => {
            const msg = {
                getFrom: () => ({ index: 99, arrayIndex: 98, moniker: 'invalid', keyInt: () => new BN(99) }),
                content: () => ({}),
                isBroadcast: true,
                wireBytes: Buffer.from([])
            };
            const [ok, err] = round4.update(msg);
            expect(ok).toBe(false);
            expect(err?.message).toContain('invalid party array index');
        });
    });

    describe('Round Completion', () => {
        test('should complete when all messages received', async () => {
            // Setup valid state
            const privateKey = new BN(123);
            const publicKey = secp256k1.g.mul(privateKey);
            data.xi = privateKey;
            data.ecdsaPub = new ECPoint(secp256k1, publicKey.getX(), publicKey.getY());

            await round4.start();

            // Simulate messages from all parties
            for (let i = 0; i < params.totalParties; i++) {
                const msg = {
                    getFrom: () => ({ index: i + 1, arrayIndex: i, moniker: `party${i + 1}`, keyInt: () => new BN(i + 1) }),
                    content: () => ({}),
                    isBroadcast: true,
                    wireBytes: Buffer.from([])
                };
                const [ok, err] = round4.update(msg);
                expect(ok).toBe(true);
                expect(err).toBeNull();
            }

            expect(round4.isComplete()).toBe(true);
            expect(end).toHaveBeenCalledWith(data);
        });
    });
});