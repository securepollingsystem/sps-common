import { ed25519 } from '@noble/curves/ed25519';
import { bls12_381 } from '@noble/curves/bls12-381';
import { randomBytes } from '@noble/hashes/utils';

export async function verifyScreedSignature({ screed, signature, publicKey }) {
  try {
    const messageBytes = new TextEncoder().encode(screed);
    let signatureBytes;
    try {
      signatureBytes = base64URLToBytes(signature);
    } catch (e) {
      console.error('Signature base64URL decode failed:', e);
      return false;
    }
    const publicKeyBytes = hexToBytes(publicKey);
    return ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
  } catch (e) {
    console.error('Signature verification failed:', e);
    return false;
  }
}

export function genKey(setPrivateKey: (key: string) => void) { // Generate a new ed25519 private key
  const privateKeyBytes = ed25519.utils.randomSecretKey();
  const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);

  console.log("Signing public key:", bytesToHex(publicKeyBytes));
  const privateKeyHex = bytesToHex(privateKeyBytes);
  console.log("Signing private key:", privateKeyHex);

  setPrivateKey(privateKeyHex); // sets the private key hex string in the state
  localStorage.setItem("myPrivateKeyHex", privateKeyHex); // saves the private key
}

export function registerPublicKey(privateKey: string, setRegistrationToken: (token: string) => void) {
  if (!privateKey || privateKey == "nothing found in local storage") {
    alert('You need to generate a key first!');
    return;
  }

  try {
    const privateKeyBytes = hexToBytes(privateKey);
    // The message we want to sign is the user's ed25519 pub key
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);

    // Hash the public key to H(m), a point on G1
    const messageHash = bls12_381.G1.Point.fromAffine(bls12_381.G1.hashToCurve(publicKeyBytes).toAffine());

    // Generate a random scalar `r` for blinding
    const r = bls12_381.utils.randomSecretKey();

    // Blind the message by multiplying [r]H(m)
    const blindedMessageHash = messageHash.multiply(
      bls12_381.G1.Point.Fn.fromBytes(r)
    );

    // Create blind signature by multiplying the blinded message hash with
    // the registrar's private key
    // FIXME this should be on registrar server
    const blindSignature = bls12_381.shortSignatures.sign(blindedMessageHash, registrarPrivateKey);

    // Calculate registration token by unblinding, i.e. multiplying by r^{-1}
    const registrationTokenPoint = blindSignature.multiply(
      bls12_381.G1.Point.Fn.inv(bls12_381.G1.Point.Fn.fromBytes(r))
    );

    const registrationTokenBytes = registrationTokenPoint.toBytes();

    // Verify the registration token
    // FIXME this should be done on the verifier's server
    const isValid = bls12_381.shortSignatures.verify(
      registrationTokenBytes,
      messageHash,
      registrarPublicKey.toBytes()
    );

    if (isValid) {
      setRegistrationToken(bytesToHex(registrationTokenBytes));
      // alert('Public key registered successfully! Registration token generated and verified.');
      console.log('Registration token:', bytesToHex(registrationTokenBytes));
    } else {
      alert('ERROR: Registration token failed verification!');
      console.error('Registration token verification failed');
    }

  } catch (error) {
    alert('Error registering public key: ' + error.message);
    console.error('Registration error:', error);
  }
}

export const hexToBytes = (hex: string) => { // Helper functions to convert between hex, base64, and Uint8Array
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
};

export const bytesToHex = (bytes: Uint8Array) => {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
};

export const base64URLToBytes = (base64URL: string) => {
  return Buffer.from(base64URL, 'base64url');
};

export const bytesToBase64URL = (bytes: Uint8Array) => {
  const base64 = btoa(String.fromCharCode(...bytes)); // Replace + with -, / with _, and remove padding
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};

export function getSignedScreedObject(loadedScreed: object, privateKey: string) {
  if (!privateKey || privateKey == "nothing found in local storage") {
    alert('You can\'t upload your screed without an encryption key!');
    return null;
  }

  try {
    const privateKeyBytes = hexToBytes(privateKey);
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
    const publicKeyHex = bytesToHex(publicKeyBytes);

    const screedString = JSON.stringify(loadedScreed);
    const messageBytes = new TextEncoder().encode(screedString);

    // Sign the message using Ed25519
    const signatureBytes = ed25519.sign(messageBytes, privateKeyBytes);
    const signature = bytesToBase64URL(signatureBytes);

    return { // Create the signed screed object
      screed: screedString,
      signature,
      publicKey: publicKeyHex
    };
  } catch (error) {
    alert('Error creating signed screed: ' + error.message);
    return null;
  }
}

export function getPublicKeyForDisplay(privateKey: string) { // Helper function to get public key for display
  if (!privateKey || privateKey == "nothing found in local storage") {
    return "";
  }
  try {
    const privateKeyBytes = hexToBytes(privateKey);
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
    const publicKeyHex = bytesToHex(publicKeyBytes);
    console.log('publicKeyHex:',publicKeyHex);
    // Split into two parts like the original code
    const part1 = publicKeyHex.slice(0, 32);
    const part2 = publicKeyHex.slice(32, 64);
    return `${part1} ${part2}`;
  } catch (error) {
    return error.message; //"Error displaying public key";
  }
}

// Hard-coded BLS keypair for the registrar
// FIXME this should be on registrar server
function hexToUint8Array(hex: string) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

const registrarPrivateKeyHex  = '2ed099c28c00366fa36668b3ae09ab82e927bc1e5b6c8d0cf4a101d9407ff4a7';
export const registrarPrivateKey = hexToUint8Array(registrarPrivateKeyHex);
// Pubkey in G2
export const registrarPublicKey = bls12_381.shortSignatures.getPublicKey(registrarPrivateKey);
