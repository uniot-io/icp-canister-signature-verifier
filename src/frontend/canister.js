import { Certificate, Cbor, reconstruct, compare, lookup_path } from '@dfinity/agent'
import { unwrapDER } from '@dfinity/identity'
import { lebDecode, PipeArrayBuffer } from '@dfinity/candid'
import { Principal } from '@dfinity/principal'
import { sha256 } from '@noble/hashes/sha256'

const DEFAULT_MAX_CERT_TIME_OFFSET = 30 * 24 * 60 * 60 * 1000 // 30 days

const CANISTER_SIGNATURE_OID = Uint8Array.from([
  ...[0x30, 0x0c], // SEQUENCE
  ...[0x06, 0x0a], // OID with 10 bytes
  ...[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb8, 0x43, 0x01, 0x02] // OID DFINITY
])

const parsePublicKey = (publicKey) => {
  const rawKey = unwrapDER(publicKey, CANISTER_SIGNATURE_OID)
  const canisterIdLen = rawKey[0]
  const rawCanisterId = rawKey.slice(1, 1 + canisterIdLen)
  const canisterId = Principal.fromUint8Array(rawCanisterId)
  const seed = rawKey.slice(1 + canisterIdLen)

  return { canisterId, seed }
}

const verifyCertifiedData = async ({ certificate, tree, rootKey, canisterId, maxCertTimeOffset }) => {
  const cert = await Certificate.create({ certificate, rootKey, canisterId })

  const decodedTime = lebDecode(new PipeArrayBuffer(cert.lookup(['time'])))
  const certTime = Number(decodedTime / BigInt(1_000_000)) // Convert from nanos to millis
  const now = Date.now()
  if (certTime - maxCertTimeOffset > now || certTime + maxCertTimeOffset < now) {
    throw new Error('Certificate has expired or is not yet valid')
  }

  const reconstructed = await reconstruct(tree)
  const witness = cert.lookup(['canister', canisterId.toUint8Array(), 'certified_data'])

  if (!witness) {
    // Could not find certified data for this canister in the certificate
    throw new Error('Could not find certified data for this canister in the certificate')
  }

  // First validate that the Tree is as good as the certification
  if (compare(witness, reconstructed) !== 0) {
    // Witness != Tree passed in ic-certification
    throw new Error('Witness != Tree passed in ic-certification')
  }

  return true
}

const lookupPathInTree = ({ seed, msg, canisterSigTree }) => {
  const msgHash = sha256.create().update(msg).digest()
  const seedHash = sha256.create().update(seed).digest()
  const tree = lookup_path(['sig', seedHash, msgHash], canisterSigTree)
  if (!tree) {
    const toHexString = (byteArray) => Buffer.from(byteArray).toString('hex')
    throw new Error(`The signature tree doesn't contain sig/${toHexString(seedHash)}/${toHexString(msgHash)} path`)
  }
  if (tree.byteLength !== 0) {
    throw new Error('The result of `lookup_path` in the signature tree was not a leaf with an empty content')
  }
  return true
}

export const verifyCanisterSig = async (
  challengeBytes,
  delegationSignatureBytes,
  identityPublicKeyBytes,
  rootKey,
  maxCertTimeOffset = DEFAULT_MAX_CERT_TIME_OFFSET
) => {
  try {
    const signatureDecoded = Cbor.decode(delegationSignatureBytes)
    const certificate = signatureDecoded.certificate
    const tree = signatureDecoded.tree

    const { canisterId, seed } = parsePublicKey(identityPublicKeyBytes)
    const verified = await verifyCertifiedData({ certificate, tree, rootKey, canisterId, maxCertTimeOffset })
    if (verified) {
      return lookupPathInTree({ seed, msg: challengeBytes, canisterSigTree: tree })
    }
  } catch (e) {
    console.error(e)
  }

  return false
}
