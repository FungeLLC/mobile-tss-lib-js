// // __tests__/eddsa/keygen/integration.test.ts
// import { KeygenParams } from '../../../eddsa/keygen/KeygenParams';
// import { LocalParty } from '../../../eddsa/keygen/LocalParty';
// import { CurveParams, KeygenConfig } from '../../../common/Types';
// import { ec as EC } from 'elliptic';
// import BN from 'bn.js';
// import crypto from 'crypto';

// describe('EdDSA Keygen Integration', () => {
// 	//skip all these tests for now



// 	const partyCount = 3;
// 	const threshold = 2;
// 	let ec: EC;
// 	let curveParams: CurveParams;
// 	let parties: LocalParty[];
// 	let messages: any[] = [];

// 	const mockRandomSource = {
// 		randomBytes: (size: number) => crypto.randomBytes(size)
// 	};

// 	beforeAll(() => {
// 		ec = new EC('ed25519');
// 		curveParams = {
// 			n: new BN('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 16),
// 			g: ec.g,
// 			curve: ec,
// 			p: new BN('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', 16)
// 		};
// 	});

// 	beforeEach(() => {
// 		messages = [];
// 		const config: KeygenConfig = {
// 			partyCount,
// 			threshold,
// 			curve: curveParams,
// 			randomSource: mockRandomSource,
// 			proofParams: {
// 				iterations: 128,
// 				hashLength: 32,
// 				primeBits: 256
// 			}
// 		};

// 		parties = Array(partyCount).fill(null).map((_, i) =>
// 			new LocalParty(
// 				new KeygenParams(config),
// 				(msg) => messages.push({ from: i, msg }),
// 				() => { }
// 			)
// 		);
// 	});

// 	it('should complete key generation successfully', async () => {
// 		// Start all parties
// 		await Promise.all(parties.map(p => p.start()));

// 		while (messages.length > 0 || !parties.every(p => p.isKeyGenComplete())) {
// 			const currentMessages = [...messages];
// 			messages = [];

// 			// Process each message sequentially
// 			for (const { from, msg } of currentMessages) {
// 				for (let i = 0; i < parties.length; i++) {
// 					if (i !== from) {
// 						const [ok, err] = await parties[i].update(msg);
// 						if (!ok || err) {
// 							throw err;
// 						}
// 					}
// 				}
// 			}
// 		}

// 		const pubKeys = parties.map(p => p.getPublicKey());
// 		expect(pubKeys.every(pk => pk !== undefined)).toBe(true);

// 		for (let i = 1; i < pubKeys.length; i++) {
// 			expect(pubKeys[i]?.equals(pubKeys[0]!)).toBe(true);
// 		}
// 	});

// 	it('should fail with invalid threshold', () => {
// 		const invalidConfig: KeygenConfig = {
// 			partyCount,
// 			threshold: partyCount + 1, // Invalid: threshold > partyCount
// 			curve: curveParams,
// 			randomSource: mockRandomSource,
// 			proofParams: {
// 				iterations: 128,
// 				hashLength: 32,
// 				primeBits: 256
// 			}
// 		};

// 		expect(() => {
// 			new KeygenParams(invalidConfig);
// 		}).toThrow('threshold must be less than or equal to party count');
// 	});
// });