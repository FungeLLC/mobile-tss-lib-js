import { Round5 } from '../../../ecdsa/keygen/Round5';
import { KeygenParams } from '../../../ecdsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../ecdsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../ecdsa/keygen/LocalTempData';
import { PartyID } from '../../../ecdsa/keygen/interfaces';
import { ECPoint } from '../../../crypto/ECPoint';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import crypto from 'crypto';
import { RandomSource } from '../../../common/Types';


describe('Round5 (ECDSA)', () => {
    let params: KeygenParams;
    let data: LocalPartySaveData;
    let temp: LocalTempData;
    let out: jest.Mock;
    let end: jest.Mock;
    let round5: Round5;
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
        round5 = new Round5(params, data, temp, out, end);
    });

    describe('Initialization', () => {
        test('should initialize with round number 5', () => {
            expect(round5.number).toBe(5);
        });

        test('should not allow double start', async () => {
            await round5.start();
            const error = await round5.start();
            expect(error?.message).toBe('round already started');
        });
    });

    describe('Final Key Validation', () => {
        test('should fail if ecdsaPub is not set', async () => {
            const error = await round5.start();
            expect(error?.message).toBe('ECDSA public key not finalized in Round5');
        });

        test('should complete successfully with valid public key', async () => {
            // Setup valid public key
            const G = new ECPoint(secp256k1, secp256k1.g.getX(), secp256k1.g.getY());
            data.ecdsaPub = G.mul(new BN(123));

            const error = await round5.start();
            expect(error).toBeNull();
            expect(end).toHaveBeenCalledWith(data);
        });
    });

    describe('Message Handling', () => {
        test('should accept any valid message', () => {
            const msg = {
                getFrom: () => ({ index: 2, arrayIndex: 1, moniker: 'party2', keyInt: () => new BN(2) } as PartyID),
                content: () => ({}),
                isBroadcast: true,
                wireBytes: Buffer.alloc(0)
            };
            const [ok, err] = round5.update(msg);
            expect(ok).toBe(true);
            expect(err).toBeNull();
        });
    });

    describe('Round Completion', () => {
        test('should end keygen process', async () => {
            // Setup final state
            const G = new ECPoint(secp256k1, secp256k1.g.getX(), secp256k1.g.getY());
            data.ecdsaPub = G.mul(new BN(123));

            await round5.start();
            expect(end).toHaveBeenCalledWith(data);
        });
    });
});