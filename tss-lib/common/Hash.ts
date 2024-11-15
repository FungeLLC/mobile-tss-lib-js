import crypto from 'crypto';
import BN from 'bn.js';

const hashInputDelimiter = Buffer.from('$');

export function SHA512_256(...inputs: Buffer[]): Buffer {
	const state = crypto.createHash('sha512-256');
	const inLen = inputs.length;
	if (inLen === 0) {
		return Buffer.alloc(0);
	}
	let bzSize = 0;
	const inLenBz = Buffer.alloc(8);
	inLenBz.writeUInt32LE(inLen, 0);
	for (const input of inputs) {
		bzSize += input.length;
	}
	const dataCap = inLenBz.length + bzSize + inLen + (inLen * 8);
	let data = Buffer.alloc(0);
	data = Buffer.concat([data, inLenBz], dataCap);
	for (const input of inputs) {
		data = Buffer.concat([data, input, hashInputDelimiter]);
		const dataLen = Buffer.alloc(8);
		dataLen.writeUInt32LE(input.length, 0);
		data = Buffer.concat([data, dataLen]);
	}
	state.update(data);
	return state.digest();
}

export function SHA512_256i(...inputs: BN[]): BN {
	const state = crypto.createHash('sha512-256');
	const inLen = inputs.length;
	if (inLen === 0) {
		return new BN(0);
	}
	let bzSize = 0;
	const inLenBz = Buffer.alloc(8);
	inLenBz.writeUInt32LE(inLen, 0);
	const ptrs = inputs.map(input => input.toArrayLike(Buffer));
	for (const ptr of ptrs) {
		bzSize += ptr.length;
	}
	const dataCap = inLenBz.length + bzSize + inLen + (inLen * 8);
	let data = Buffer.alloc(0);
	data = Buffer.concat([data, inLenBz], dataCap);
	for (const ptr of ptrs) {
		data = Buffer.concat([data, ptr, hashInputDelimiter]);
		const dataLen = Buffer.alloc(8);
		dataLen.writeUInt32LE(ptr.length, 0);
		data = Buffer.concat([data, dataLen]);
	}
	state.update(data);
	return new BN(state.digest());
}

export function SHA512_256i_TAGGED(tag: Buffer, ...inputs: BN[]): BN {
	const tagBz = SHA512_256(tag);
	const state = crypto.createHash('sha512-256');
	state.update(tagBz);
	state.update(tagBz);
	const inLen = inputs.length;
	if (inLen === 0) {
		return new BN(0);
	}
	let bzSize = 0;
	const inLenBz = Buffer.alloc(8);
	inLenBz.writeUInt32LE(inLen, 0);
	const ptrs = inputs.map(input => input ? input.toArrayLike(Buffer) : Buffer.alloc(0));
	for (const ptr of ptrs) {
		bzSize += ptr.length;
	}
	const dataCap = inLenBz.length + bzSize + inLen + (inLen * 8);
	let data = Buffer.alloc(0);
	data = Buffer.concat([data, inLenBz], dataCap);
	for (const ptr of ptrs) {
		data = Buffer.concat([data, ptr, hashInputDelimiter]);
		const dataLen = Buffer.alloc(8);
		dataLen.writeUInt32LE(ptr.length, 0);
		data = Buffer.concat([data, dataLen]);
	}
	state.update(data);
	return new BN(state.digest());
}

export function SHA512_256iOne(input: BN): BN {
	const state = crypto.createHash('sha512-256');
	if (!input) {
		return new BN(0);
	}
	const data = input.toArrayLike(Buffer);
	state.update(data);
	return new BN(state.digest());
}

export function RejectionSample(q: BN, eHash: BN): BN {
	return eHash.mod(q);
}