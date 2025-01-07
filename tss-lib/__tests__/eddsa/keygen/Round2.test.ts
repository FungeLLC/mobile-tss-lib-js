import { Round1 } from '../../../eddsa/keygen/Round1';
import { Round2 } from '../../../eddsa/keygen/Round2';
import { KGRound2Message1 } from '../../../eddsa/keygen/KGRound2Message1';
import { KGRound2Message2 } from '../../../eddsa/keygen/KGRound2Message2';
import { Share } from '../../../crypto/VSS';
import { ECPoint } from '../../../crypto/ECPoint';
import { ProofFac } from '../../../crypto/FACProof';
import BN from 'bn.js';
import { KeygenParams } from '../../../eddsa/keygen/KeygenParams';
import { LocalPartySaveData } from '../../../eddsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../../../eddsa/keygen/LocalTempData';
import { PartyID } from '../../../eddsa/keygen/interfaces';
import { KGRound1Message } from '../../../eddsa/keygen/Round1';

describe('Round2', () => {
	let params: KeygenParams;
	let data: LocalPartySaveData;
	let temp: LocalTempData;
	let out: jest.Mock;
	let end: jest.Mock;
	let round2: Round2;

	beforeEach(() => {
		params = {
			partyID: () => ({ index: 1 } as PartyID),
			totalParties: 3,
			threshold: 1,
			ec: { n: { toString: () => '72370055773322622139731865630429942408' }, curve: {} },
			parties: [{ index: 1, keyInt: () => 1 }, { index: 2, keyInt: () => 2 }, { index: 3, keyInt: () => 3 }],
			rand: { randomBytes: (size: number) => Buffer.alloc(size) },
		} as any;
		data = new LocalPartySaveData(params.totalParties);
		temp = new LocalTempData(params.totalParties);
		out = jest.fn();
		end = jest.fn();
		round2 = new Round2(params, data, temp, out, end);
	});

	test('should not proceed if round1 messages are missing', () => {
		expect(round2.canProceed()).toBe(false);
	});

    test('should proceed after receiving all Round1 messages', async () => {
        temp.kgRound1Messages[0] = new KGRound1Message({
            index: 1,
            arrayIndex: 0,
            moniker: '1'
        } as PartyID, Buffer.from([1]));
        temp.kgRound1Messages[1] = new KGRound1Message({
            index: 2,
            arrayIndex: 1,
            moniker: '2'
        } as PartyID, Buffer.from([2]));
        temp.kgRound1Messages[2] = new KGRound1Message({
            index: 3,
            arrayIndex: 2,
            moniker: '3'
        } as PartyID, Buffer.from([3]));
        // Update ok1 and ok2 to simulate message reception
        for (let i = 0; i < params.totalParties; i++) {
            round2['ok1'][i] = true;
            round2['ok2'][i] = true;
        }
        await round2.start();
        expect(round2.canProceed()).toBe(true);
        for (let i = 0; i < params.totalParties; i++) {
            round2['ok1'][i] = true;
            round2['ok2'][i] = true;
        }
        expect(round2.canProceed()).toBe(true);
    });

    test('should start once', async () => {
        temp.kgRound1Messages[0] = new KGRound1Message({
            index: 1,
            arrayIndex: 0,
            moniker: '1'
        } as PartyID, Buffer.from([1]));
        temp.kgRound1Messages[1] = new KGRound1Message({
            index: 2,
            arrayIndex: 1,
            moniker: '2'
        } as PartyID, Buffer.from([2]));
        temp.kgRound1Messages[2] = new KGRound1Message({
            index: 3,
            arrayIndex: 2,
            moniker: '3'
        } as PartyID, Buffer.from([3]));
        await round2.start();
        const error = await round2.start();
        expect(error?.message).toBe('round already started');
    });

});

describe('Round2 with Round1 setup', () => {
    let round1: Round1;
    let round2: Round2;
    let params: KeygenParams;
    let data: LocalPartySaveData;
    let temp: LocalTempData;
    let proofFac: ProofFac;
    
    beforeEach(async () => {
        // Set up params as before
        params = {
            partyID: () => ({ index: 1, arrayIndex: 0 } as PartyID),
            totalParties: 3,
            threshold: 1,
            ec: { n: { toString: () => '72370055773322622139731865630429942408' }, curve: {} },
            parties: [{ index: 1, keyInt: () => 1 }, { index: 2, keyInt: () => 2 }, { index: 3, keyInt: () => 3 }],
            rand: { randomBytes: (size: number) => Buffer.alloc(size) },
        } as any;
        

        proofFac = new ProofFac(
            new BN(1), // P
            new BN(1), // Q
            new BN(1), // A
            new BN(1), // B
            new BN(1), // T
            new BN(1), // a
            new BN(1), // b
            new BN(1), // z
            new BN(1), // w
            new BN(1), // s
            new BN(1), // s1
        );

        // Create and run Round1 first
        data = new LocalPartySaveData(params.totalParties);
        temp = new LocalTempData(params.totalParties);
        round1 = new Round1(params, data, temp, jest.fn(), jest.fn());
        await round1.start();
        
        // Create Round2
        round2 = new Round2(params, data, temp, jest.fn(), jest.fn());
    });



    test('should handle Round2Message1 correctly', async () => {
        const msg = new KGRound2Message1(
            { index: 1, arrayIndex: 0, toString: () => 'party1' } as PartyID,
            { index: 2, arrayIndex: 1, toString: () => 'party2' } as PartyID,
            new BN(123),
            proofFac
        );

        await round2.start();
        const [success, error] = round2.update(msg);
        expect(success).toBe(true);
        expect(error).toBeNull();
        expect(round2['ok1'][1]).toEqual(true); // Expecting array with first element true
    });

    test('should handle Round2Message2 correctly', async () => {
        const msg = new KGRound2Message2(
            { index: 2, arrayIndex: 1 } as PartyID,
            { deCommitPolyG: [new BN(1), new BN(2)] }
        );
        
        const [success, error] = round2.update(msg);
        expect(success).toBe(true);
        expect(error).toBeNull();
        expect(round2['ok2'][1]).toBe(true); // Using arrayIndex for array access
    });

    test('should reject invalid party index', async () => {
        const msg = new KGRound2Message1(
            { index: 99, arrayIndex: 98 } as PartyID,
            { index: 100, arrayIndex: 99 } as PartyID,
            new BN(123),
            proofFac
        );
        
        const [success, error] = round2.update(msg);
        expect(success).toBe(false);
        expect(error?.message).toBe('invalid party array index');
    });

    test('should complete round when all messages received', async () => {
        const endMock = jest.fn();
        round2 = new Round2(params, data, temp, jest.fn(), endMock);
        // add shares to temp data
        temp.shares[0] = new Share(2 ,new BN(1), new BN(2));
        temp.shares[1] = new Share(2, new BN(2), new BN(4));
        temp.shares[2] = new Share(2, new BN(3), new BN(6));
        round2.start();
        // Send all required messages
        for (let i = 1; i <= params.totalParties; i++) {
            if (i === params.partyID().index) continue;
            
            const msg1 = new KGRound2Message1(
                { index: 1, arrayIndex: 0, toString: () => 'party1' } as PartyID,
                { index: i, arrayIndex: i-1, toString: () => `party${i}` } as PartyID,
                new BN(123),
                proofFac
            );
            const msg2 = new KGRound2Message2(
                { index: i, arrayIndex: i-1 } as PartyID,
                { deCommitPolyG: [new BN(1), new BN(2)] }
            );
            
            round2.update(msg1);
            round2.update(msg2);
        }
        
        expect(round2.canProceed()).toBe(true);
        expect(endMock).toHaveBeenCalled();
    });
});
