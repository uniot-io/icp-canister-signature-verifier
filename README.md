# ICP Canister Signature Verifier

This project is a web-based application for verifying Canister Signatures on the Internet Computer (ICP). It uses the DFINITY libraries and integrates with the Internet Identity service for authentication.

Here's a brief breakdown of what each key file does:

- `lib.rs`: Contains the Rust logic for verifying Canister Signatures. It exports a function to WebAssembly that accepts a challenge, a signature, a canister public key, and a root public key, and then verifies the canister signature against them.

- `app.js`: The main application logic. This file handles user interactions, such as authenticating with the Internet Identity service, signing messages, and verifying canister signatures using the exported function from the Rust code.

## Installation & Running

### Prerequisites

- Ensure you have Node.js and npm installed on your machine.
- Have the Rust compiler and wasm-pack tool installed for WebAssembly builds.

### Steps

1. **Clone the project**:

   ```
   git clone https://github.com/uniot-io/icp-canister-signature-verifier.git
   cd icp-canister-signature-verifier
   ```

2. **Install dependencies**:

   ```
   npm install
   ```

3. **Build the WebAssembly module**:

   ```
   npm run build-wasm
   ```

4. **Deploy the canisters** (assuming you have `dfx` CLI tool installed):

   ```
   dfx deploy
   ```

5. **Start the Vite development server**:

   ```
   npm start
   ```

6. The application should now be accessible on `http://localhost:5173` (or the port specified in your Vite configuration).

## Usage

1. Click on the "Login" button to authenticate using the Internet Identity service.
2. Once authenticated, the app will display the user's principal and initiate the signature verification process.
3. The console will log relevant information, such as public keys, OIDs, and verification results.
