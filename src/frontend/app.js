import asn1 from 'asn1.js'
import { AuthClient } from '@dfinity/auth-client'
import { requestIdOf } from '@dfinity/agent'
import { ed25519 } from '@noble/curves/ed25519'
import init, { verify_canister_sig } from '@/../rs/pkg/icp_canister_signature_verifier.js'

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

export async function runApp () {
  document.querySelector('#login-btn').addEventListener('click', async () => {
    const authClient = await AuthClient.create({ keyType: 'Ed25519' })

    await new Promise((resolve) => {
      authClient.login({
        identityProvider: import.meta.env.VITE_APP_II_URL,
        onSuccess: () => {
          resolve(true)
        }
      })
    })

    const identity = authClient.getIdentity()
    const principal = identity.getPrincipal().toString()
    document.querySelector('#principal-label').innerHTML = principal
    console.log('Principal:\n', principal)

    console.log('Identity Type:\n', identity.constructor.name)
    console.log('Identity _inner Type:\n', identity._inner.constructor.name)

    const identityPubKeyDerBuf = Buffer.from(identity.getPublicKey().toDer())
    console.log('Identity Public Key (Der):\n', identityPubKeyDerBuf.toString('hex'))
    const identityPubKeySpki = SPKI.decode(identityPubKeyDerBuf, 'der')
    console.log('Identity Public Key Algorithm OID:\n', identityPubKeySpki.algorithm.id.join('.'))
    console.log('Canister signatures OID:\n', '1.3.6.1.4.1.56387.1.2')
    const identityPubKeySubjectBuf = Buffer.from(identityPubKeySpki.subjectPublicKey.data)
    console.log('Identity Public Key (subject):\n', identityPubKeySubjectBuf.toString('hex'))

    const innerPubKeyDerBuf = Buffer.from(identity._inner.getPublicKey().toDer())
    console.log('Identity _inner Public Key (Der):\n', innerPubKeyDerBuf.toString('hex'))
    const innerPubKeySpki = SPKI.decode(innerPubKeyDerBuf, 'der')
    console.log('Identity _inner Public Key Algorithm OID:\n', innerPubKeySpki.algorithm.id.join('.'))
    console.log('Ed25519 OID:\n', '1.3.101.112')
    const innerPubKeySubjectBuf = Buffer.from(innerPubKeySpki.subjectPublicKey.data)
    console.log('Identity _inner Public Key (subject):\n', innerPubKeySubjectBuf.toString('hex'))

    const msg = 'Hello World!'
    console.log('Message to sign:\n', msg)
    const signature = await identity.sign(new TextEncoder().encode(msg))
    console.log('Identity Signature:\n', Buffer.from(signature).toString('hex'))
    console.log('This produces the signature made by the session key (identity._inner).')
    console.log('It can be verified with the corresponding key (identity._inner.getPublicKey()).')

    const verified = ed25519.verify(new Uint8Array(signature), Buffer.from(msg), new Uint8Array(innerPubKeySubjectBuf))
    console.log('Ed25519 Signature verified:\n', verified)

    const rootPubKeyDerBuf = Buffer.from(import.meta.env.VITE_APP_IC_ROOT_KEY, 'hex')
    console.log('Root Public Key (Der):\n', rootPubKeyDerBuf.toString('hex'))
    const rootPubKeySpki = SPKI.decode(rootPubKeyDerBuf, 'der')
    console.log('Root Public Key Algorithm OID:\n', rootPubKeySpki.algorithm.id.join('.'))
    console.log('Delegation OID:\n', '1.3.6.1.4.1.44668.5.3.1.2.1')
    const rootPubKeySubjectBuf = Buffer.from(rootPubKeySpki.subjectPublicKey.data)
    console.log('Root Public Key (subject):\n', rootPubKeySubjectBuf.toString('hex'))

    const delegationChain = identity.getDelegation().toJSON()
    const delegationObj = delegationChain.delegations.find((delegation) => {
      return Buffer.from(delegation.delegation.pubkey, 'hex').equals(innerPubKeyDerBuf)
    })

    const delegation = {
      pubkey: innerPubKeyDerBuf.buffer,
      expiration: BigInt('0x' + delegationObj.delegation.expiration)
    }

    const domainSeparator = new TextEncoder().encode('\x1Aic-request-auth-delegation')
    const challengeBytes = new Uint8Array([...domainSeparator, ...new Uint8Array(requestIdOf(delegation))])
    console.log('Challenge Bytes:\n', Buffer.from(challengeBytes).toString('hex'))

    const rootPubKeyBytes = new Uint8Array(rootPubKeyDerBuf)
    const identityPublicKeyBytes = new Uint8Array(identityPubKeyDerBuf)
    const delegationSignatureBytes = new Uint8Array(Buffer.from(delegationObj.signature, 'hex'))

    await init()
    const canisterVerified = verify_canister_sig(challengeBytes, delegationSignatureBytes, identityPublicKeyBytes, rootPubKeyBytes)
    console.log('Canister Signature verified:\n', canisterVerified)
  })
}
