import { TssError } from '../tss-lib/common/TssError';
import { Parameters, PartyID, Round, MessageFromTss, ParsedMessage } from '../tss-lib/ecdsa/keygen/interfaces';
import { LocalPartySaveData } from '../tss-lib/ecdsa/keygen/LocalPartySaveData';
import { LocalTempData } from '../tss-lib/ecdsa/keygen/LocalTempData';
import BN from 'bn.js';


// Define the Messenger interface
export interface Messenger {
	send(from: string, to: string, message: string): Promise<void>;
}

// Define the LocalStateAccessor interface
export interface LocalStateAccessor {
	saveLocalState(key: string, state: string): Promise<void>;
	getLocalState(key: string): Promise<string>;
}

// Define the KeygenRequest interface
export interface KeygenRequest {
	chainCodeHex: string;
	getAllParties(): string[];
	localPartyID: string;
}

// Define the KeygenResponse interface
export interface KeygenResponse {
	pubKey: string;
}

// Define the KeysignRequest interface
export interface KeysignRequest {
	messageToSign: string;
	pubKey: string;
	getKeysignCommitteeKeys(): string[];
}

// Define the KeysignResponse interface
export interface KeysignResponse {
	msg: string;
	r: string;
	s: string;
	derSignature: string;
	recoveryID: string;
}

// Define the LocalState interface
export interface LocalState {
	keygenCommitteeKeys: string[];
	localPartyKey: string;
	chainCodeHex?: string;
	ecdsaLocalData?: any;
	eddsaLocalData?: any;
	resharePrefix?: string;
	pubKey?: string;
}


export { TssError, Parameters, PartyID, Round, MessageFromTss, ParsedMessage, LocalPartySaveData, LocalTempData, BN };