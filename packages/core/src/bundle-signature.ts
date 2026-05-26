// Ed25519 bundle signature verification.
//
// Network-fetched bundles are only accepted if their detached Ed25519
// signature verifies against the PUBLIC key pinned in `constants.ts`. This is
// the authenticity check the plain `contentHash` (a recomputable integrity
// checksum) does not provide: a checksum proves the bytes weren't corrupted,
// not that they came from the control plane. The signing private key is held
// only by the API, so verifying the signature against the pinned public key
// confirms a bundle originated there before it is adopted.
//
// The built-in/offline baseline pack is locally trusted and is never fetched,
// so it does not pass through here; only bundles pulled over the network are
// verified.

import { createPublicKey, verify, type KeyObject } from 'node:crypto';

import {
  BUNDLE_SIGNATURE_ALG,
  BUNDLE_SIGNING_KEY_ID,
  BUNDLE_SIGNING_PUBLIC_KEY_SPKI_B64,
} from './constants.js';
import { canonicalBundleBytes, type Bundle } from './types.js';

let cachedPublicKey: KeyObject | null = null;

function pinnedPublicKey(): KeyObject {
  if (cachedPublicKey !== null) return cachedPublicKey;
  cachedPublicKey = createPublicKey({
    key: Buffer.from(BUNDLE_SIGNING_PUBLIC_KEY_SPKI_B64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  return cachedPublicKey;
}

/**
 * Verify a bundle's Ed25519 signature against the pinned public key. Returns
 * `null` if the signature is valid, or a human-readable reason string if it is
 * not — callers treat any non-null result as a rejection.
 *
 * Checks, in order: the algorithm tag is the one we understand, the keyId
 * matches the pinned key, and the detached signature verifies over the
 * canonical content bytes (the bundle minus its `signature` envelope).
 */
export function verifyBundleSignature(bundle: Bundle): string | null {
  const { signature: envelope, ...content } = bundle;

  // A network-pulled bundle with no signature envelope is unauthenticated and
  // is rejected (the schema permits `undefined` only so the locally-trusted
  // offline pack, which never reaches this verifier, can parse).
  if (envelope === undefined) {
    return 'bundle has no signature';
  }

  if (envelope.signatureAlg !== BUNDLE_SIGNATURE_ALG) {
    return `unsupported signature algorithm '${envelope.signatureAlg}' (expected '${BUNDLE_SIGNATURE_ALG}')`;
  }
  if (envelope.keyId !== BUNDLE_SIGNING_KEY_ID) {
    return `unknown signing keyId '${envelope.keyId}' (pinned '${BUNDLE_SIGNING_KEY_ID}')`;
  }

  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(envelope.signature, 'base64');
  } catch {
    return 'signature is not valid base64';
  }
  if (sigBytes.length === 0) {
    return 'signature is empty';
  }

  const messageBytes = canonicalBundleBytes(content);

  let ok = false;
  try {
    ok = verify(null, messageBytes, pinnedPublicKey(), sigBytes);
  } catch (err) {
    return `signature verification threw: ${(err as Error).message}`;
  }
  if (!ok) {
    return 'signature does not verify against the pinned public key';
  }
  return null;
}
