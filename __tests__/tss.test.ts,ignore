// Import necessary libraries and dependencies for testing
import { ServiceImpl } from '../tss/tss';
import { Messenger, LocalStateAccessor, KeygenRequest, KeysignRequest, MessageFromTss } from '../tss/interfaces';
import * as assert from 'assert';

// Jest framework is used for testing
import { jest } from '@jest/globals';

// Create mock implementations for Messenger and LocalStateAccessor
const mockMessenger: Messenger = {
    send: jest.fn(async (from: string, to: string, message: string) => {
        console.log(`Mock Send Message from ${from} to ${to}: ${message}`);
    }),
};

const mockStateAccessor: LocalStateAccessor = {
    saveLocalState: jest.fn(async (key: string, state: string) => {
        console.log(`Mock Save State for ${key}`);
    }),
    getLocalState: jest.fn(async (key: string) => {
        console.log(`Mock Get State for ${key}`);
        return '{}';
    }),
};

// Define the ServiceImpl instance for testing
const service = new ServiceImpl(mockMessenger, mockStateAccessor, true);

// Tests for each function and method defined in tss.go equivalent

describe('ServiceImpl', () => {
    test('applyData should push message to inboundMessageCh', () => {
        const message = 'test message';
        service.applyData(message);
        expect(service['inboundMessageCh']).toContain(message);
    });

    test('getParties should return sorted party IDs and localPartyID', () => {
        const allPartyKeys = ['party1', 'party2', 'party3'];
        const localPartyKey = 'party2';
        const [partyIDs, localPartyID] = service['getParties'](allPartyKeys, localPartyKey, '');
        expect(localPartyID.moniker).toBe(localPartyKey);
        expect(partyIDs.length).toBe(allPartyKeys.length);
    });

    test('keygenECDSA should return a valid KeygenResponse', async () => {
        const keygenReq: KeygenRequest = {
            chainCodeHex: 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
            getAllParties: () => ['party1', 'party2', 'party3'],
            localPartyID: 'party1',
        };
        const response = await service.keygenECDSA(keygenReq);
        expect(response.pubKey).not.toBeNull();
        expect(response.pubKey).toMatch(/^04[0-9a-fA-F]{128}$/); // Validate uncompressed public key format
    });

    test('keygenEdDSA should return a valid KeygenResponse', async () => {
        const keygenReq: KeygenRequest = {
            chainCodeHex: 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
            getAllParties: () => ['party1', 'party2', 'party3'],
            localPartyID: 'party1',
        };
        const response = await service.keygenEdDSA(keygenReq);
        expect(response.pubKey).not.toBeNull();
        expect(response.pubKey).toMatch(/^[0-9a-fA-F]{64}$/); // Validate Ed25519 public key format
    });

    test('keysignECDSA should return a valid KeysignResponse', async () => {
        const keysignReq: KeysignRequest = {
            messageToSign: Buffer.from('Test Message').toString('base64'),
            pubKey: '04abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd', // Dummy ECDSA public key
            getKeysignCommitteeKeys: () => ['party1', 'party2', 'party3'],
        };
        const response = await service.keysignECDSA(keysignReq);
        expect(response.r).not.toBeNull();
        expect(response.s).not.toBeNull();
        expect(response.derSignature).toBeDefined();
    });

    test('keysignEdDSA should return a valid KeysignResponse', async () => {
        const keysignReq: KeysignRequest = {
            messageToSign: Buffer.from('Test Message').toString('base64'),
            pubKey: 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd', // Dummy EdDSA public key
            getKeysignCommitteeKeys: () => ['party1', 'party2', 'party3'],
        };
        const response = await service.keysignEdDSA(keysignReq);
        expect(response.r).not.toBeNull();
        expect(response.s).not.toBeNull();
        expect(response.derSignature).toBeDefined();
    });

    test('validateKeysignRequest should throw error for missing fields', () => {
        const keysignReq: Partial<KeysignRequest> = {
            messageToSign: '',
        };
        expect(() => service['validateKeysignRequest'](keysignReq as KeysignRequest)).toThrow('KeysignCommitteeKeys is empty');
    });

    test('applyMessageToTssInstance should log the application of message', () => {
        const msg = Buffer.from(JSON.stringify({
            wireBytes: new Uint8Array([1, 2, 3]),
            from: 'party1',
            isBroadcast: true
        })).toString('base64');

        const sortedPartyIds = [{ moniker: 'party1' }];
        const result = service['applyMessageToTssInstance']({}, msg, sortedPartyIds);
        expect(result).toBe('Message successfully applied');
    });
});

// Run the tests using Jest
// To run the tests, use the command: jest tss.test.ts
