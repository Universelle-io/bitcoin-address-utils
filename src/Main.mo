import P2pkh "mo:bitcoin/bitcoin/P2pkh";
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Iter "mo:base/Iter";
import Text "mo:base/Text";
import BitcoinTypes "mo:bitcoin/bitcoin/Types";
import Curves "mo:bitcoin/ec/Curves";
import Ripemd160 "mo:bitcoin/Ripemd160";
import Bech32 "mo:bitcoin/Bech32";
import Sha256 "mo:sha2/Sha256";

import Utils "./Utils";
import DebugUtils "DebugUtils";

module {

    public type AddressType = {
        #P2PKH;
        #P2WPKH;
        #P2TR;
    };

    public type ECDSAPublicKeyReply = {
        public_key : Blob;
        chain_code : Blob;
    };

    public type SignWithECDSAReply = {
        signature : Blob;
    };

    public type SignWithECDSA = {
        message_hash : Blob;
        derivation_path : [Blob];
        key_id : EcdsaKeyId;
    };

    type EcdsaCurve = { #secp256k1 };
    type EcdsaKeyId = {
        curve : EcdsaCurve;
        name : Text;
    };

    public type ECDSAPublicKey = {
        canister_id : ?Principal;
        derivation_path : [Blob];
        key_id : EcdsaKeyId;
    };

    public type EcdsaCanisterActor = actor {
        ecdsa_public_key : ECDSAPublicKey -> async ECDSAPublicKeyReply;
        sign_with_ecdsa : SignWithECDSA -> async SignWithECDSAReply;
    };

    let CURVE : Curves.Curve = Curves.secp256k1;

    public func get_derivation_path_from_owner(owner : Principal, subaccount : ?Blob) : [Blob] {
        let base = [Principal.toBlob(owner)];
        switch subaccount {
            case null base;
            case (?sa) Array.append(base, [sa]);
        };
    };

    /// P2PKH

    public func public_key_to_p2pkh_address(
        network : BitcoinTypes.Network,
        public_key_bytes : [Nat8],
    ) : Text {
        Debug.print("🔑 public_key_bytes (hex): " # DebugUtils.toHex(public_key_bytes));
        let address = P2pkh.deriveAddress(network, (public_key_bytes, CURVE));
        Debug.print("✅ Derived address directly from SEC1-compressed pubkey: " # address);
        address;
    };

    public func get_p2pkh_address(
        owner : Principal,
        derivation_path : [Blob],
        network : BitcoinTypes.Network,
        ecdsa_canister_actor : EcdsaCanisterActor,
        key_name : Text,
    ) : async Text {
        Debug.print("📩 Getting public key for owner: " # Principal.toText(owner));
        Debug.print(
            "🔗 Derivation path (hex blobs): [" #
            Text.join(", ", Iter.fromArray(Array.map(derivation_path, func(b : Blob) : Text = DebugUtils.toHex(Blob.toArray(b))))) #
            "]"
        );

        let public_key_reply = await ecdsa_canister_actor.ecdsa_public_key({
            canister_id = null;
            derivation_path = derivation_path;
            key_id = { curve = #secp256k1; name = key_name };
        });

        let pubkey_bytes = Blob.toArray(public_key_reply.public_key);
        Debug.print("📦 Public key from ECDSA canister (hex): " # DebugUtils.toHex(pubkey_bytes));

        public_key_to_p2pkh_address(network, pubkey_bytes);
    };

    /// P2WPKH

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

    public func get_p2wpkh_address(
        owner : Principal,
        derivation_path : [Blob],
        network : BitcoinTypes.Network,
        ecdsa_canister_actor : EcdsaCanisterActor,
        key_name : Text,
    ) : async Text {
        Debug.print("📩 Getting public key for owner: " # Principal.toText(owner));
        Debug.print(
            "🔗 Derivation path (hex blobs): [" #
            Text.join(", ", Iter.fromArray(Array.map(derivation_path, func(b : Blob) : Text = DebugUtils.toHex(Blob.toArray(b))))) #
            "]"
        );

        let public_key_reply = await ecdsa_canister_actor.ecdsa_public_key({
            canister_id = null;
            derivation_path = derivation_path;
            key_id = { curve = #secp256k1; name = key_name };
        });

        let pubkey_bytes = Blob.toArray(public_key_reply.public_key);
        Debug.print("📦 Public key from ECDSA canister (hex): " # DebugUtils.toHex(pubkey_bytes));

        public_key_to_p2wpkh_address(network, pubkey_bytes);
    };

};
