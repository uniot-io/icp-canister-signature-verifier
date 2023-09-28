extern crate wasm_bindgen;
extern crate web_sys;

use ic_crypto_standalone_sig_verifier::user_public_key_from_bytes;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_types::crypto::threshold_sig::IcRootOfTrust;
use ic_types::crypto::{CanisterSig, CanisterSigOf, SignableMock};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    Ok(())
}

#[wasm_bindgen]
pub fn verify_canister_sig(
    challenge: &[u8],
    signature: &[u8],
    canister_pk_der: &[u8],
    root_pk_der: &[u8],
) -> bool {
    let root_pk = match parse_threshold_sig_key_from_der(root_pk_der) {
        Ok(pk) => pk,
        Err(e) => {
            web_sys::console::error_1(&format!("Failed to convert root public key from DER format: {:?}", e).into());
            return false;
        }
    };
    let root_of_trust = IcRootOfTrust::from(root_pk);

    let canister_pk = match user_public_key_from_bytes(canister_pk_der) {
        Ok(pk) => pk,
        Err(e) => {
            web_sys::console::error_1(&format!("Failed to convert canister public key from DER format: {:?}", e).into());
            return false;
        }
    };

    let canister_sig: CanisterSigOf<SignableMock> = CanisterSigOf::from(CanisterSig(signature.to_vec()));

    match ic_crypto_standalone_sig_verifier::verify_canister_sig(
        challenge,
        &canister_sig.get_ref().0,
        &canister_pk.0.key,
        root_of_trust,
    ) {
        Ok(_) => true,
        Err(e) => {
            web_sys::console::error_1(&format!("Signature verification failed: {:?}", e).into());
            false
        }
    }
}
