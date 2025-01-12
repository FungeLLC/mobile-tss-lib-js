// Import the necessary cryptographic and utility libraries
import * as crypto from 'crypto';
import * as EC from 'elliptic';
import { Messenger, LocalStateAccessor, KeygenRequest, KeygenResponse, KeysignRequest, KeysignResponse, LocalState, MessageFromTss } from './interfaces';
import { GetThreshold, GetHexEncodedPubKey, HashToInt, GetDerivePathBytes, Contains, derivingPubkeyFromPath, GetDERSignature } from './utils';

const ec = new EC.ec('secp256k1');

// TypeScript implementation of ServiceImpl class
export class ServiceImpl {
	private preParams: any;
	private messenger: Messenger;
	private stateAccessor: LocalStateAccessor;
	private inboundMessageCh: string[];
	private resharePrefix: string;

	constructor(msg: Messenger, stateAccessor: LocalStateAccessor, createPreParam: boolean) {
		if (!msg) {
			throw new Error('nil messenger');
		}
		if (!stateAccessor) {
			throw new Error('nil state accessor');
		}
		this.messenger = msg;
		this.stateAccessor = stateAccessor;
		this.inboundMessageCh = [];
		this.resharePrefix = '';

		if (createPreParam) {
			this.preParams = this.generatePreParams();
		}
	}

	private generatePreParams(): any {
		const random = crypto.randomBytes(32);
		return ec.keyFromPrivate(random);
	}

	public applyData(msg: string): void {
		this.inboundMessageCh.push(msg);
	}

	private getParties(allPartyKeys: string[], localPartyKey: string, keyPrefix: string): [any[], any] {
		let localPartyID: any;
		let unSortedPartiesID: any[] = [];
		allPartyKeys.sort();
		for (let idx = 0; idx < allPartyKeys.length; idx++) {
			const item = allPartyKeys[idx];
			const key = BigInt(`0x${keyPrefix}${Buffer.from(item).toString('hex')}`);
			const partyID = { index: idx.toString(), key, moniker: item };
			if (item === localPartyKey) {
				localPartyID = partyID;
			}
			unSortedPartiesID.push(partyID);
		}
		const partyIDs = this.sortPartyIDs(unSortedPartiesID);
		return [partyIDs, localPartyID];
	}

	private sortPartyIDs(partyIDs: any[]): any[] {
		return partyIDs.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
	}

	public async keygenECDSA(req: KeygenRequest): Promise<KeygenResponse> {
		if (!req.chainCodeHex) {
			throw new Error('ChainCodeHex is empty');
		}
		const chaincode = Buffer.from(req.chainCodeHex, 'hex');
		if (chaincode.length !== 32) {
			throw new Error('Invalid chain code length');
		}
		const [partyIDs, localPartyID] = this.getParties(req.getAllParties(), req.localPartyID, '');
		const ctx = {};
		const curve = ec.curve;
		const totalPartiesCount = req.getAllParties().length;
		const threshold = GetThreshold(totalPartiesCount);
		const params = { curve, ctx, localPartyID, totalPartiesCount, threshold };
		const outCh: any[] = [];
		const endCh: any[] = [];
		const errCh: any[] = [];
		const localState: LocalState = {
			keygenCommitteeKeys: req.getAllParties(),
			localPartyKey: req.localPartyID,
			chainCodeHex: req.chainCodeHex,
			resharePrefix: '',
		};
		const localPartyECDSA = this.createLocalParty(params, outCh, endCh, this.preParams);
		try {
			await localPartyECDSA.start();
		} catch (e) {
			console.error('Failed to start keygen process', e);
			errCh.push('error');
		}
		const pubKey = await this.processKeygen(localPartyECDSA, errCh, outCh, endCh, [], localState, partyIDs);
		if (!pubKey) {
			console.error('Failed to process keygen');
			throw new Error('Keygen failed');
		}
		return {
			pubKey,
		};
	}

	// Function to handle keygenEdDSA
	public async keygenEdDSA(req: KeygenRequest): Promise<KeygenResponse> {
		const [partyIDs, localPartyID] = this.getParties(req.getAllParties(), req.localPartyID, '');
		const ctx = { partyIDs }; // Create TSS context
		const curve = new EC.ec('ed25519'); // Edwards curve for EdDSA
		const totalPartiesCount = req.getAllParties().length;
		const threshold = GetThreshold(totalPartiesCount);

		const params = { curve, ctx, localPartyID, totalPartiesCount, threshold }; // TSS Parameters
		const outCh: any[] = []; // Message channel
		const endCh: any[] = []; // Result channel
		const errCh: any[] = [];
		const localState: LocalState = {
			keygenCommitteeKeys: req.getAllParties(),
			localPartyKey: req.localPartyID,
		};

		const localPartyEDDSA = this.createLocalParty(params, outCh, endCh, null);

		try {
			await localPartyEDDSA.start();
		} catch (e) {
			console.error('Failed to start keygen process', e);
			errCh.push('error');
		}

		const pubKey = await this.processKeygen(localPartyEDDSA, errCh, outCh, [], endCh, localState, partyIDs);
		if (!pubKey || pubKey.length !== 64) { // Ensure pubKey is valid and has the expected length
			console.error('Failed to process keygen or invalid key length');
			throw new Error('Keygen failed or returned an invalid public key');
		}
		return {
			pubKey,
		};
	}


	private createLocalParty(params: any, outCh: any[], endCh: any[], preParams: any) {
		return {
			params,
			start: async () => {
				console.log('Starting local party with params:', params);
			},
		};
	}


	private async processKeygen(
		localParty: any,
		errCh: any[],
		outCh: any[],
		ecdsaEndCh: any[],
		eddsaEndCh: any[],
		localState: LocalState,
		sortedPartyIds: any[]
	): Promise<string | null> {
		return new Promise((resolve, reject) => {
			const handleIncomingMessages = async () => {
				while (true) {
					const err = errCh.shift();
					if (err) {
						reject('Failed to start keygen process');
						return;
					}

					if (outCh.length > 0) {
						const outMsg = outCh.shift();
						if (outMsg) {
							const { wireBytes, r } = outMsg.WireBytes();
							const messageFromTss: MessageFromTss = {
								wireBytes,
								from: r.From.moniker,
								isBroadcast: r.IsBroadcast,
							};
							const jsonBytes = JSON.stringify(messageFromTss);
							const outboundPayload = Buffer.from(jsonBytes).toString('base64');

							if (r.IsBroadcast || !r.To) {
								for (const item of localState.keygenCommitteeKeys) {
									if (item !== localState.localPartyKey) {
										await this.messenger.send(r.From.moniker, item, outboundPayload);
									}
								}
							} else {
								for (const item of r.To) {
									await this.messenger.send(r.From.moniker, item.moniker, outboundPayload);
								}
							}
						}
					}

					if (this.inboundMessageCh.length > 0) {
						const msg = this.inboundMessageCh.shift();
						if (msg) {
							try {
								this.applyMessageToTssInstance(localParty, msg, sortedPartyIds);
							} catch (error) {
								reject(`Failed to apply message to TSS instance: ${error}`);
								return;
							}
						}
					}

					if (ecdsaEndCh.length > 0) {
						const saveData = ecdsaEndCh.shift();
						if (saveData) {
							const pubKey = GetHexEncodedPubKey(saveData.ECDSAPub);
							localState.pubKey = pubKey;
							localState.ecdsaLocalData = saveData;
							await this.saveLocalStateData(localState);
							resolve(pubKey);
							return;
						}
					}

					if (eddsaEndCh.length > 0) {
						const saveData = eddsaEndCh.shift();
						if (saveData) {
							const pubKey = GetHexEncodedPubKey(saveData.EDDSAPub);
							localState.pubKey = pubKey;
							localState.eddsaLocalData = saveData;
							await this.saveLocalStateData(localState);
							resolve(pubKey);
							return;
						}
					}
				}
			};

			handleIncomingMessages();

			setTimeout(() => {
				reject('Keygen timeout, keygen did not finish in 2 minutes');
			}, 2 * 60 * 1000);
		});
	}
	// Function to save local state data
	private async saveLocalStateData(localState: LocalState): Promise<void> {
		try {
			const result = JSON.stringify(localState, null, 2);
			if (!localState.pubKey) {
				throw new Error('Public key is undefined');
			}
			await this.stateAccessor.saveLocalState(localState.pubKey, result);
		} catch (err) {
			throw new Error(`Failed to save local state data, error: ${err}`);
		}
	}

	public async keysignECDSA(req: KeysignRequest): Promise<KeysignResponse> {
		if (!req.messageToSign) {
			throw new Error('MessageToSign is empty');
		}
		const bytesToSign = Buffer.from(req.messageToSign, 'base64');
		const localStateStr = await this.stateAccessor.getLocalState(req.pubKey);
		if (!localStateStr) {
			throw new Error('Failed to get local state');
		}
		const localState: LocalState = JSON.parse(localStateStr);
		if (!localState.ecdsaLocalData || !localState.ecdsaLocalData.ecdsaPub) {
			throw new Error('nil ecdsa pub key');
		}
		const keysignCommittee = req.getKeysignCommitteeKeys();
		if (!Contains(keysignCommittee, localState.localPartyKey)) {
			throw new Error('local party not in keysign committee');
		}
		const [keysignPartyIDs, localPartyID] = this.getParties(keysignCommittee, localState.localPartyKey, localState.resharePrefix || '');
		const threshold = GetThreshold(localState.keygenCommitteeKeys.length);
		const curve = ec.curve;
		const outCh: any[] = [];
		const endCh: any[] = [];
		const errCh: any[] = [];
		const ctx = { partyIDs: keysignPartyIDs };
		const params = { curve, ctx, localPartyID, totalPartiesCount: keysignPartyIDs.length, threshold };
		const m = HashToInt(bytesToSign, curve);
		const keysignParty = this.createKeysignParty(m, params, localState.ecdsaLocalData, outCh, endCh);
		try {
			await keysignParty.start();
		} catch (e) {
			console.error('Failed to start keysign process', e);
			errCh.push('error');
		}
		const signature = await this.processKeySign(keysignParty, errCh, outCh, endCh, keysignPartyIDs);
		if (!signature) {
			console.error('Failed to process keysign');
			throw new Error('Keysign failed');
		}
		const derSig = GetDERSignature(BigInt(signature.r), BigInt(signature.s));
		return {
			msg: req.messageToSign,
			r: signature.r,
			s: signature.s,
			derSignature: derSig,
			recoveryID: signature.signatureRecovery,
		};
	}

	public async keysignEdDSA(req: KeysignRequest): Promise<KeysignResponse> {
		if (!req.messageToSign) {
			throw new Error('MessageToSign is empty');
		}
		const bytesToSign = Buffer.from(req.messageToSign, 'base64');
		const localStateStr = await this.stateAccessor.getLocalState(req.pubKey);
		if (!localStateStr) {
			throw new Error('Failed to get local state');
		}
		const localState: LocalState = JSON.parse(localStateStr);
		if (!localState.eddsaLocalData || !localState.eddsaLocalData.eddsaPub) {
			throw new Error('nil eddsa pub key');
		}

		const keysignCommittee = req.getKeysignCommitteeKeys();
		if (!Contains(keysignCommittee, localState.localPartyKey)) {
			throw new Error('local party not in keysign committee');
		}
		const [keysignPartyIDs, localPartyID] = this.getParties(keysignCommittee, localState.localPartyKey, localState.resharePrefix || '');
		const threshold = GetThreshold(localState.keygenCommitteeKeys.length);
		const outCh: any[] = [];
		const endCh: any[] = [];
		const errCh: any[] = [];
		const ctx = { partyIDs: keysignPartyIDs };
		const params = { ctx, localPartyID, totalPartiesCount: keysignPartyIDs.length, threshold };
		const m = new EC.ec('ed25519').keyFromPrivate(bytesToSign).getPrivate();
		const keysignParty = this.createKeysignParty(m, params, localState.eddsaLocalData, outCh, endCh);
		try {
			await keysignParty.start();
		} catch (e) {
			console.error('Failed to start keysign process', e);
			errCh.push('error');
		}
		const signature = await this.processKeySign(keysignParty, errCh, outCh, endCh, keysignPartyIDs);
		if (!signature) {
			console.error('Failed to process keysign');
			throw new Error('Keysign failed');
		}
		const derSig = GetDERSignature(BigInt(signature.r), BigInt(signature.s));
		return {
			msg: req.messageToSign,
			r: signature.r,
			s: signature.s,
			derSignature: derSig,
			recoveryID: signature.signatureRecovery,
		};
	}

	// Function to validate keysign request
	public validateKeysignRequest(req: KeysignRequest): void {
		if (!req) {
			throw new Error('Request is null or undefined');
		}
		if (!req.messageToSign) {
			throw new Error('MessageToSign is empty');
		}
		if (!req.pubKey) {
			throw new Error('Public key is empty');
		}
		if (!req.getKeysignCommitteeKeys || req.getKeysignCommitteeKeys().length === 0) {
			throw new Error('KeysignCommitteeKeys is empty');
		}
	}

	// Function to apply a message to a TSS instance
	public applyMessageToTssInstance(localParty: any, msg: string, sortedPartyIds: any[]): string {
		const messageFromTss = JSON.parse(Buffer.from(msg, 'base64').toString('utf-8')) as MessageFromTss;
		const fromParty = sortedPartyIds.find(p => p.moniker === messageFromTss.from);
		if (!fromParty) {
			throw new Error(`Failed to find from party with moniker: ${messageFromTss.from}`);
		}

		const updateResult = localParty.updateFromBytes(messageFromTss.wireBytes, fromParty, messageFromTss.isBroadcast);
		if (updateResult) {
			throw new Error(`Failed to apply message to TSS instance: ${updateResult}`);
		}

		return 'Message successfully applied';
	}


	private createKeysignParty(m: any, params: any, localData: any, outCh: any[], endCh: any[]) {
		return {
			start: async () => {
				console.log('Starting keysign party with params:', params);
			},
		};
	}

    // Function to process keysign
    private async processKeySign(
        localParty: any,
        errCh: any[],
        outCh: any[],
        endCh: any[],
        sortedPartyIds: any[]
    ): Promise<any> {
        return new Promise((resolve, reject) => {
            const handleIncomingMessages = async () => {
                while (true) {
                    const err = errCh.shift();
                    if (err) {
                        reject('Failed to start keysign process');
                        return;
                    }

                    if (outCh.length > 0) {
                        const outMsg = outCh.shift();
                        if (outMsg) {
                            const { wireBytes, r } = outMsg.WireBytes();
                            const messageFromTss: MessageFromTss = {
                                wireBytes,
                                from: r.From.moniker,
                                isBroadcast: r.IsBroadcast,
                            };
                            const jsonBytes = JSON.stringify(messageFromTss);
                            const outboundPayload = Buffer.from(jsonBytes).toString('base64');

                            if (r.IsBroadcast) {
                                for (const item of sortedPartyIds) {
                                    if (item.moniker !== localParty.partyID().moniker) {
                                        await this.messenger.send(r.From.moniker, item.moniker, outboundPayload);
                                    }
                                }
                            } else {
                                for (const item of r.To) {
                                    await this.messenger.send(r.From.moniker, item.moniker, outboundPayload);
                                }
                            }
                        }
                    }

                    if (this.inboundMessageCh.length > 0) {
                        const msg = this.inboundMessageCh.shift();
                        if (msg) {
                            try {
                                this.applyMessageToTssInstance(localParty, msg, sortedPartyIds);
                            } catch (error) {
                                reject(`Failed to apply message to TSS instance: ${error}`);
                                return;
                            }
                        }
                    }

                    if (endCh.length > 0) {
                        const signatureData = endCh.shift();
                        if (signatureData) {
                            resolve(signatureData);
                            return;
                        }
                    }
                }
            };

            handleIncomingMessages();

            setTimeout(() => {
                reject('Keysign timeout, keysign did not finish in 1 minute');
            }, 1 * 60 * 1000);
        });
    }
}
