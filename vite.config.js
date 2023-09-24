import path from 'path'
import CBOR from 'cbor'

const DFX_NETWORK = process.env.DFX_NETWORK || 'local'

async function init () {
  let canisters

  try {
    canisters = require(path.resolve('.dfx', 'local', 'canister_ids.json'))
  } catch (error) {
    console.log('No local canister_ids.json found.')
  }

  if (DFX_NETWORK === 'local') {
    const replicaStatusResponse = await fetch('http://localhost:33695/api/v2/status')
    if (!replicaStatusResponse.ok) {
      console.error('Failed to fetch the local replica status')
    }
    const localReplicaStatus = CBOR.decode(await replicaStatusResponse.arrayBuffer())

    process.env.VITE_APP_II_URL = `http://localhost:4943/?canisterId=${canisters.internet_identity[DFX_NETWORK]}`
    process.env.VITE_APP_IC_ROOT_KEY = Buffer.from(localReplicaStatus.value.root_key).toString('hex')
  } else {
    process.env.VITE_APP_II_URL = 'https://identity.ic0.app'
    process.env.VITE_APP_IC_ROOT_KEY =
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814' +
      'c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d968' +
      '5f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484' +
      'b01291091c5f87b98883463f98091a0baaae'
  }
}

export default async () => {
  await init()

  return {
    publicDir: './src/frontend/public',
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src/frontend')
      }
    }
  }
}
