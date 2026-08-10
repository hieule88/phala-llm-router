/**
 * @leviathan/wallet-aci — the wallet side of wallet-bound ACI.
 *
 * See ../../../docs/wallet-bound-aci.md for the protocol, and README.md for
 * how to wire this into the Leviathan extension.
 */

export {
  BIND_PURPOSE,
  REQUEST_PURPOSE,
  GOLDILOCKS_P,
  jcs,
  statementWordBytes,
  requestSigningBytes,
  bytesToHex,
  hexToBytes,
  bytesToB64,
  randomHex
} from './canonical.js';
export type { BindStatement, Json } from './canonical.js';

export { deriveAciSeed, deriveAciKeys } from './keys.js';
export type { AciKeys } from './keys.js';

export {
  AciError,
  DEFAULT_AUTHORIZATION,
  openAciSession,
  signedFetch,
  closeAciSession,
  revokeAllAciSessions
} from './client.js';
export type { AciAuthorization, AciSession, FalconWordSigner } from './client.js';
