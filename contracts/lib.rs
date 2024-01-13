#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod dauth_verifier {
    use ink_env::ecdsa_recover;
    use ink_env::hash::{Blake2x256, CryptoHash};
    use ink_prelude::vec::Vec;

    #[ink(storage)]
    pub struct DauthVerifier {
        /// Stores an public address from the node for later verify
        signer_addr: [u8; 32],
    }

    impl DauthVerifier {
        #[ink(constructor)]
        pub fn new(init_addr: [u8; 32]) -> Self {
            Self {
                signer_addr: init_addr,
            }
        }

        // verify the signature against request_id, account_hash,
        // return true for valid signature
        // false for invalid signature
        #[ink(message)]
        pub fn verify(
            &self,
            message: Vec<u8>,
            signature: [u8; 65], // Ethereum signature format
        ) -> bool {
            let mut message_hash = [0_u8; 32];
            Blake2x256::hash(&message, &mut message_hash);
            let mut recovered_public = [0_u8; 33];
            let res = ecdsa_recover(&signature, &message_hash, &mut recovered_public);
            match res {
                Ok(_) => {}
                Err(_) => return false,
            }
            recovered_public[1..] == self.signer_addr
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// We test if the default constructor does its job.
        #[ink::test]
        fn verify_signature() {}

        /// We test a simple use case of our contract.
        #[ink::test]
        fn verify_signature_invalid() {
            let verifier = DauthVerifier::new([0_u8; 32]);
            let message = b"hello world".to_vec();
            let signature = [0_u8; 65];
            assert_eq!(verifier.verify(message, signature), false);
        }
    }
}
