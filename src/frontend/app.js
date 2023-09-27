import asn1 from 'asn1.js'
import * as CBOR from 'cbor-web'
import * as tweetnacl from 'tweetnacl'
import { AuthClient } from '@dfinity/auth-client'
import { requestIdOf, Certificate, HttpAgent } from '@dfinity/agent'
import { Principal } from '@dfinity/principal'
import wasmInit, { verify_canister_sig } from '@/../rs/pkg/icp_canister_signature_verifier.js'

// prettier-ignore
const SPKI = asn1.define('SPKI', function () {
  this.seq().obj(
    this.key('algorithm').seq().obj(
      this.key('id').objid(),
      this.key('parameters').objid().optional()
    ),
    this.key('subjectPublicKey').bitstr()
  )
})

class SignatureResearch {
  async login () {
    this._client = await AuthClient.create({ keyType: 'Ed25519' })

    await new Promise((resolve) => {
      this._client.login({
        identityProvider: import.meta.env.VITE_APP_II_URL,
        onSuccess: () => {
          resolve(true)
        }
      })
    })

    this._identity = this._client.getIdentity()
    this._agent = new HttpAgent({ host: import.meta.env.VITE_APP_IC_AGENT_HOST })
    await this._agent.fetchRootKey()
  }

  async signStringWithSessionKey (msg) {
    return this._identity.sign(new TextEncoder().encode(msg))
  }

  getDelegation () {
    const sessionPubKey = Buffer.from(this._identity._inner.getPublicKey().toDer())
    const delegationChain = this._identity.getDelegation()
    return delegationChain.delegations.find((delegation) => {
      return Buffer.from(delegation.delegation.pubkey).equals(sessionPubKey)
    })
  }

  getPublicKey () {
    return this._identity.getPublicKey().toDer()
  }

  getPrincipal () {
    return this._identity.getPrincipal().toString()
  }

  logDebugInfo () {
    console.log('Identity Type:\n', this._identity.constructor.name)
    console.log('Identity _inner Type:\n', this._identity._inner.constructor.name)

    const identityPubKeyDerBuf = Buffer.from(this._identity.getPublicKey().toDer())
    const identityPubKeySpki = SPKI.decode(identityPubKeyDerBuf, 'der')
    const identityPubKeySubjectBuf = Buffer.from(identityPubKeySpki.subjectPublicKey.data)
    console.log('Identity Public Key (Der):\n', identityPubKeyDerBuf.toString('hex'))
    console.log('Identity Public Key (subject):\n', identityPubKeySubjectBuf.toString('hex'))
    console.log('Identity Public Key Algorithm OID:\n', identityPubKeySpki.algorithm.id.join('.'))
    console.log('Canister signatures OID:\n', '1.3.6.1.4.1.56387.1.2')

    const innerPubKeyDerBuf = Buffer.from(this._identity._inner.getPublicKey().toDer())
    const innerPubKeySpki = SPKI.decode(innerPubKeyDerBuf, 'der')
    const innerPubKeySubjectBuf = Buffer.from(innerPubKeySpki.subjectPublicKey.data)
    console.log('Identity _inner Public Key (Der):\n', innerPubKeyDerBuf.toString('hex'))
    console.log('Identity _inner Public Key (subject):\n', innerPubKeySubjectBuf.toString('hex'))
    console.log('Identity _inner Public Key Algorithm OID:\n', innerPubKeySpki.algorithm.id.join('.'))
    console.log('Ed25519 OID:\n', '1.3.101.112')

    const rootPubKeyDerBuf = Buffer.from(this._agent.rootKey)
    const rootPubKeySpki = SPKI.decode(rootPubKeyDerBuf, 'der')
    const rootPubKeySubjectBuf = Buffer.from(rootPubKeySpki.subjectPublicKey.data)
    console.log('Root Public Key (Der):\n', rootPubKeyDerBuf.toString('hex'))
    console.log('Root Public Key (subject):\n', rootPubKeySubjectBuf.toString('hex'))
    console.log('Root Public Key Algorithm OID:\n', rootPubKeySpki.algorithm.id.join('.'))
    console.log('Root Delegation OID:\n', '1.3.6.1.4.1.44668.5.3.1.2.1')

    console.log('----------------------------------------')
  }
}

class VerifierResearch {
  async init (identityPublicKey, sessionDelegation) {
    this._identityPublicKey = identityPublicKey
    this._sessionDelegation = sessionDelegation
    this._agent = new HttpAgent({ host: import.meta.env.VITE_APP_IC_AGENT_HOST })
    await this._agent.fetchRootKey()
  }

  generateMessage () {
    const msg = {
      timestamp: Date.now(),
      nonce: Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
    }
    return JSON.stringify(msg)
  }

  async verifyPrinicpal (principal) {
    const identityPrincipal = Principal.selfAuthenticating(new Uint8Array(this._identityPublicKey))
    return identityPrincipal.toString() === principal
  }

  async verifyMessageSignature (msg, signature) {
    const pubKeySpki = SPKI.decode(Buffer.from(this._sessionDelegation.delegation.pubkey), 'der')

    return tweetnacl.sign.detached.verify(
      new TextEncoder().encode(msg),
      new Uint8Array(signature),
      new Uint8Array(pubKeySpki.subjectPublicKey.data)
    )
  }

  checkSessionKeyExpiration (msg) {
    const msgObj = JSON.parse(msg)
    const expiration = new Date(Number(this._sessionDelegation.delegation.expiration / BigInt(1000000))).getTime()
    return msgObj.timestamp <= expiration
  }

  verifySession () {
    return {
      rustImpl: async () => {
        const domainSeparator = new TextEncoder().encode('\x1Aic-request-auth-delegation')
        const challengeBytes = new Uint8Array([
          ...domainSeparator,
          ...new Uint8Array(requestIdOf(this._sessionDelegation.delegation))
        ])
        const rootPubKeyBytes = new Uint8Array(this._agent.rootKey)
        const identityPublicKeyBytes = new Uint8Array(this._identityPublicKey)
        const delegationSignatureBytes = new Uint8Array(this._sessionDelegation.signature)

        await wasmInit()
        return verify_canister_sig(challengeBytes, delegationSignatureBytes, identityPublicKeyBytes, rootPubKeyBytes)
      },
      jsImpl: async () => {
        const signatureDecoded = CBOR.decode(this._sessionDelegation.signature)
        const certificate = signatureDecoded.value.certificate
        const rootKey = new Uint8Array(this._agent.rootKey)
        const pubKeySpki = SPKI.decode(Buffer.from(this._identityPublicKey), 'der')
        const rawKey = new Uint8Array(pubKeySpki.subjectPublicKey.data)
        const canisterId = Principal.fromUint8Array(rawKey.slice(1, 1 + rawKey[0]))

        return Certificate.create({ certificate, rootKey, canisterId })
          .then(() => true)
          .catch((err) => {
            console.log(err)
            return false
          })
        // TODO: lookup path in canister sig tree
      }
    }
  }
}

export async function runApp () {
  document.querySelector('#login-btn').addEventListener('click', async () => {
    const signatureResearch = new SignatureResearch()
    const verifierResearch = new VerifierResearch()

    await signatureResearch.login()
    signatureResearch.logDebugInfo()
    document.querySelector('#principal-label').innerHTML = signatureResearch.getPrincipal()

    await verifierResearch.init(signatureResearch.getPublicKey(), signatureResearch.getDelegation())
    const msg = verifierResearch.generateMessage()
    console.log('Message to sign:\n', msg)

    const msgSignature = await signatureResearch.signStringWithSessionKey(msg)

    const principalVerified = await verifierResearch.verifyPrinicpal(signatureResearch.getPrincipal())
    console.log('Principal verified:\n', principalVerified)

    const sessionVerifiedRustImpl = await verifierResearch.verifySession().rustImpl()
    console.log('Session verified (Rust impl):\n', sessionVerifiedRustImpl)

    const sessionVerifiedJsImpl = await verifierResearch.verifySession().jsImpl()
    console.log('Session verified (JS impl):\n', sessionVerifiedJsImpl)

    const msgSignatureVerified = await verifierResearch.verifyMessageSignature(msg, msgSignature)
    console.log('Message Signature verified:\n', msgSignatureVerified)

    const sessionKeyExpirationVerified = verifierResearch.checkSessionKeyExpiration(msg)
    console.log('Session Key Expiration verified:\n', sessionKeyExpirationVerified)
  })
}
