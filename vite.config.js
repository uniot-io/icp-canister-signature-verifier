import path from 'path'

const DFX_NETWORK = process.env.DFX_NETWORK || 'local'
const IC_REPLICA_PORT = process.env.IC_REPLICA_PORT || 4943

async function init () {
  let canisters

  try {
    canisters = require(path.resolve('.dfx', 'local', 'canister_ids.json'))
  } catch (error) {
    console.log('No local canister_ids.json found.')
  }

  if (DFX_NETWORK === 'local') {
    process.env.VITE_APP_II_URL = `http://localhost:${IC_REPLICA_PORT}/?canisterId=${canisters.internet_identity[DFX_NETWORK]}`
    process.env.VITE_APP_IC_AGENT_HOST = `http://localhost:${IC_REPLICA_PORT}`
  } else {
    process.env.VITE_APP_II_URL = 'https://identity.ic0.app'
    process.env.VITE_APP_IC_AGENT_HOST = 'https://ic0.app'
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
