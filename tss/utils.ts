// Utility functions for TSS implementation
import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';

const ec = new EC('secp256k1');

// Function for getting the threshold based on the total number of parties
export function GetThreshold(totalParties: number): number {
    return Math.floor(totalParties / 2) + 1;
}

// Function to get a hex-encoded public key
export function GetHexEncodedPubKey(pubKey: any): string {
    if (!pubKey || typeof pubKey.getX !== 'function' || typeof pubKey.getY !== 'function') {
        throw new Error('Invalid public key provided');
    }
    const x = pubKey.getX().toString(16).padStart(64, '0');
    const y = pubKey.getY().toString(16).padStart(64, '0');
    return `04${x}${y}`; // Format: 04 + X + Y (Uncompressed format)
}

// Hash a message to an integer value
export function HashToInt(message: Buffer, curve: any): bigint {
    const hash = crypto.createHash('sha256').update(message).digest();
    return BigInt('0x' + hash.toString('hex')) % curve.n; // Ensure the hash is within the curve order
}

// Function for getting derived path bytes
export function GetDerivePathBytes(derivePath: string): Buffer {
    const pathElements = derivePath.split('/').filter(element => element !== 'm');
    const bufferArray = pathElements.map(element => {
        const hardened = element.endsWith("'");
        const index = parseInt(hardened ? element.slice(0, -1) : element, 10);
        const buf = Buffer.allocUnsafe(4);
        buf.writeUInt32BE(index + (hardened ? 0x80000000 : 0), 0);
        return buf;
    });
    return Buffer.concat(bufferArray);
}

// Check if an array contains a particular value
export function Contains(array: string[], value: string): boolean {
    return array.includes(value);
}

// Deriving a public key from a given path
export function derivingPubkeyFromPath(pubKey: any, chainCode: Buffer, path: Buffer, curve: any): [bigint, any] {
    // Derivation using HMAC-SHA512, as is common in HD Wallet schemes like BIP32
    const I = crypto.createHmac('sha512', chainCode).update(Buffer.concat([pubKey.encode(), path])).digest();
    const il = I.slice(0, 32);
    const ir = I.slice(32);
    const derivedKey = ec.keyFromPrivate(il).getPublic().add(pubKey);
    return [BigInt('0x' + il.toString('hex')), derivedKey];
}

// Generate DER formatted signature
export function GetDERSignature(r: bigint, s: bigint): string {
    const rBuffer = Buffer.from(r.toString(16).padStart(64, '0'), 'hex');
    const sBuffer = Buffer.from(s.toString(16).padStart(64, '0'), 'hex');
    return encodeDERSignature(rBuffer, sBuffer).toString('hex');
}

// Helper function to encode DER formatted signature
function encodeDERSignature(r: Buffer, s: Buffer): Buffer {
    const rEncoded = encodeDERInteger(r);
    const sEncoded = encodeDERInteger(s);
    const sequence = Buffer.concat([Buffer.from([0x30]), encodeDERLength(rEncoded.length + sEncoded.length), rEncoded, sEncoded]);
    return sequence;
}

// Helper function to encode a DER integer
function encodeDERInteger(integer: Buffer): Buffer {
    if (integer[0] & 0x80) {
        integer = Buffer.concat([Buffer.from([0x00]), integer]);
    }
    return Buffer.concat([Buffer.from([0x02]), encodeDERLength(integer.length), integer]);
}

// Helper function to encode DER length
function encodeDERLength(length: number): Buffer {
    if (length < 0x80) {
        return Buffer.from([length]);
    } else {
        const lengthBuffer = Buffer.allocUnsafe(4);
        const lenLength = lengthBuffer.writeUInt32BE(length, 0);
        return Buffer.concat([Buffer.from([0x80 + lenLength]), lengthBuffer.slice(4 - lenLength)]);
    }
}
