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
        if  (public_key_bytes.size() != 33 and public_key_bytes.size() != 65) {
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

};
