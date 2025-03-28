import P2pkh "mo:bitcoin/bitcoin/P2pkh";
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Text "mo:base/Text";
import BitcoinTypes "mo:bitcoin/bitcoin/Types";
import Curves "mo:bitcoin/ec/Curves";
import Ripemd160 "mo:bitcoin/Ripemd160";
import Bech32 "mo:bitcoin/Bech32";
import Sha256 "mo:sha2/Sha256";
import Cycles "mo:base/ExperimentalCycles";
import Nat "mo:base/Nat";
import ECDSA "mo:bitcoin/ecdsa/Ecdsa";
import Der "mo:bitcoin/ecdsa/Der";

import Utils "./Utils";
import DebugUtils "DebugUtils";
import Types "Types";

module {
    let CURVE : Curves.Curve = Curves.secp256k1;

    /// Generates a derivation path for a given owner (principal) and optional subaccount.
    /// If no subaccount is provided, the path will contain only the owner.
    /// If a subaccount is provided, it will be appended to the path.
    ///
    /// # Parameters:
    /// - `owner`: The principal (owner) to derive the path from.
    /// - `subaccount`: An optional subaccount to append to the path.
    ///
    /// # Returns:
    /// A list of `Blob` objects representing the derivation path.
    public func get_derivation_path_from_owner(owner : Principal, subaccount : ?Blob) : [Blob] {
        let base = [Principal.toBlob(owner)];
        switch subaccount {
            case null base;
            case (?sa) Array.append(base, [sa]);
        };
    };

    /// Generates a P2PKH address from a public key (compressed SEC1 format) and the specified network.
    ///
    /// # Parameters:
    /// - `network`: The Bitcoin network for which the address should be generated.
    /// - `public_key_bytes`: The public key bytes in SEC1-compressed format.
    ///
    /// # Returns:
    /// A P2PKH address in `Text` format.
    public func public_key_to_p2pkh_address(
        network : BitcoinTypes.Network,
        public_key_bytes : [Nat8],
    ) : Text {
        Debug.print("🔑 public_key_bytes (hex): " # DebugUtils.toHex(public_key_bytes));
        let address = P2pkh.deriveAddress(network, (public_key_bytes, CURVE));
        Debug.print("✅ Derived address directly from SEC1-compressed pubkey: " # address);
        address;
    };

    /// Asynchronously retrieves the P2PKH address for a given owner and derivation path from the ECDSA canister.
    ///
    /// # Parameters:
    /// - `derivation_path`: The derivation path used to derive the public key.
    /// - `network`: The Bitcoin network for which the address should be generated.
    /// - `ecdsa_canister_actor`: The ECDSA canister actor used to get the public key.
    /// - `key_name`: The name of the key to use in the canister for deriving the public key.
    ///
    /// # Returns:
    /// A P2PKH address in `Text` format.
    public func get_p2pkh_address(
        derivation_path : [Blob],
        network : BitcoinTypes.Network,
        ecdsa_canister_actor : Types.EcdsaCanisterActor,
        key_name : Text,
    ) : async Text {
        let public_key_reply = await ecdsa_canister_actor.ecdsa_public_key({
            canister_id = null;
            derivation_path = derivation_path;
            key_id = { curve = #secp256k1; name = key_name };
        });

        let pubkey_bytes = Blob.toArray(public_key_reply.public_key);

        public_key_to_p2pkh_address(network, pubkey_bytes);
    };

    /// Generates a P2WPKH address from a public key (compressed SEC1 format) and the specified network.
    /// This function will first perform a SHA256 hash followed by a RIPEMD160 hash on the public key.
    ///
    /// # Parameters:
    /// - `network`: The Bitcoin network for which the address should be generated.
    /// - `public_key_bytes`: The public key bytes in SEC1-compressed format.
    ///
    /// # Returns:
    /// A P2WPKH address in `Text` format.
    public func public_key_to_p2wpkh_address(
        network : BitcoinTypes.Network,
        public_key_bytes : [Nat8],
    ) : Text {
        if (public_key_bytes.size() != 33 and public_key_bytes.size() != 65) {
            Debug.trap("Invalid public key length: expected 33 or 65 bytes");
        };

        let sha256_hash = Sha256.fromArray(#sha256, public_key_bytes);
        let hash160 = Ripemd160.hash(Blob.toArray(sha256_hash));

        let hrp = switch network {
            case (#Mainnet) "bc";
            case (#Testnet) "tb";
            case (#Regtest) "bcrt";
        };

        let version : Nat8 = 0;
        let payload : [Nat8] = Array.append([version], hash160);

        switch (Utils.convertBits(payload, 8, 5, true)) {
            case (#ok(data5)) {
                Bech32.encode(hrp, data5, #BECH32);
            };
            case (#err(msg)) {
                Debug.trap("Failed to convert bits for Bech32 encoding: " # msg);
            };
        };
    };

    /// Asynchronously retrieves the P2WPKH address for a given owner and derivation path from the ECDSA canister.
    ///
    /// # Parameters:
    /// - `derivation_path`: The derivation path used to derive the public key.
    /// - `network`: The Bitcoin network for which the address should be generated.
    /// - `ecdsa_canister_actor`: The ECDSA canister actor used to get the public key.
    /// - `key_name`: The name of the key to use in the canister for deriving the public key.
    ///
    /// # Returns:
    /// A P2WPKH address in `Text` format.
    public func get_p2wpkh_address(
        derivation_path : [Blob],
        network : BitcoinTypes.Network,
        ecdsa_canister_actor : Types.EcdsaCanisterActor,
        key_name : Text,
    ) : async Text {
        let public_key_reply = await ecdsa_canister_actor.ecdsa_public_key({
            canister_id = null;
            derivation_path = derivation_path;
            key_id = { curve = #secp256k1; name = key_name };
        });

        let pubkey_bytes = Blob.toArray(public_key_reply.public_key);

        public_key_to_p2wpkh_address(network, pubkey_bytes);
    };

    /// Asynchronously signs a message using the ECDSA canister and the provided derivation path.
    /// The message is hashed using SHA256 before signing.
    ///
    /// # Parameters:
    /// - `message`: The text message to sign.
    /// - `derivation_path`: The derivation path used to derive the private key.
    /// - `ecdsa_canister_actor`: The ECDSA canister actor used to perform the signature.
    /// - `key_name`: The name of the key to use in the canister.
    ///
    /// # Returns:
    /// The ECDSA signature as a `Blob`.
    public func sign_message(
        message : Text,
        derivation_path : [Blob],
        ecdsa_canister_actor : Types.EcdsaCanisterActor,
        key_name : Text,
    ) : async Blob {
        // 1. Convert message to bytes and hash it with SHA256
        let message_bytes : [Nat8] = Blob.toArray(Text.encodeUtf8(message));
        let message_hash_blob : Blob = Sha256.fromArray(#sha256, message_bytes);

        // 2. Add required cycles manually (25B recommended for mainnet)
        //TODO: revisar si esto es algo que usaremos nostros
        //Cycles.add(25_000_000_000); // Uncomment this if calling from inside a shared function

        // 3. Call sign_with_ecdsa
        let signature_reply = await ecdsa_canister_actor.sign_with_ecdsa({
            message_hash = message_hash_blob;
            derivation_path = derivation_path;
            key_id = { curve = #secp256k1; name = key_name };
        });

        signature_reply.signature;
    };

    public func verify_signature(
        message : Text,
        public_key_sec1 : Blob,
        signature_blob : Blob,
    ) : Bool {
        Debug.print("📥 Verifying signature for message: \"" # message # "\"");

        let message_bytes = Blob.toArray(Text.encodeUtf8(message));
        let hash_bytes = message_bytes;

        Debug.print("🔑 Message hash (hex): " # DebugUtils.toHex(hash_bytes));

        let ?pubkey = Utils.public_key_from_sec1_compressed(public_key_sec1) else {
            Debug.print("❌ Failed to deserialize public key from SEC1 compressed format");
            return false;
        };
        Debug.print("✅ Public key deserialized");

        let signature : ECDSA.Signature = if (Array.size(Blob.toArray(signature_blob)) == 64) {
            Debug.print("ℹ️ Firma recibida está en formato RAW.");

            let ?sig = Utils.signature_from_raw(signature_blob) else {
                Debug.print("❌ Failed to deserialize RAW signature");
                return false;
            };
            sig;
        } else {
            Debug.print("ℹ️ Firma recibida está en formato DER.");

            switch (Der.decodeSignature(signature_blob)) {
                case (#ok(sig)) sig;
                case (#err(msg)) {
                    Debug.print("❌ Failed to deserialize signature from DER format: " # msg);
                    return false;
                };
            };
        };

        Debug.print("✅ Signature deserialized");
        Debug.print("🔍 r: " # Nat.toText(signature.r));
        Debug.print("🔍 s: " # Nat.toText(signature.s));

        let verified = ECDSA.verify(signature, pubkey, hash_bytes);

        if (verified) {
            Debug.print("✅ Signature verified successfully");
        } else {
            Debug.print("❌ Signature verification failed");
        };

        verified;
    };

};
