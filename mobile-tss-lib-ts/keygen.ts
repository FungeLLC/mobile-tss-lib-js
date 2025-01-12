import EC from 'elliptic';

class Keygen {
    private ec: EC.ec;

    constructor() {
        this.ec = new EC.ec('secp256k1'); // ECDSA using secp256k1 curve
    }

    // Function to generate an ECDSA key pair
    public generateECDSAKeyPair(): { publicKey: string; privateKey: string } {
        const keyPair = this.ec.genKeyPair();
        return {
            publicKey: keyPair.getPublic('hex'),
            privateKey: keyPair.getPrivate('hex')
        };
    }

    // Function to generate an EdDSA key pair using Ed25519 curve
    public generateEdDSAKeyPair(): { publicKey: string; privateKey: string } {
        const ed25519 = new EC.eddsa('ed25519');
        const keyPair = ed25519.keyFromSecret('randomSecret'); // Secret should be generated securely
        return {
            publicKey: keyPair.getPublic('hex'),
            privateKey: keyPair.getSecret('hex')
        };
    }
}
