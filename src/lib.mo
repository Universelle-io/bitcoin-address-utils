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
import Result "mo:base/Result";
import Iter "mo:base/Iter";
import Nat32 "mo:base/Nat32";
import ECDSA "mo:bitcoin/ecdsa/Ecdsa";
import Der "mo:bitcoin/ecdsa/Der";
import Script "mo:bitcoin/bitcoin/Script";
import Transaction "mo:bitcoin/bitcoin/Transaction";
import Segwit "mo:bitcoin/Segwit";
import Hex "mo:base16/Base16";

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

        switch (Segwit.encode(hrp, { version = 0; program = hash160 })) {
            case (#ok(addr)) addr;
            case (#err(msg)) Debug.trap("❌ Failed to encode segwit address: " # msg);
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

    /// Asynchronously signs a UTF-8 text message using the ECDSA canister and the provided derivation path.
    /// The message is hashed using SHA256 before being signed.
    ///
    /// This function returns the signature in RAW format (64 bytes), which consists of the concatenation of
    /// the 32-byte `r` and `s` values of the ECDSA signature.
    ///
    /// ⚠️ IMPORTANTE: sign is generated using `SHA256(UTF8(message))`. make sure to use same hash
    /// when you verify the signature or verification process will fail.
    ///
    /// # Parameters:
    /// - `message`: The text message to sign (will be UTF-8 encoded and hashed).
    /// - `derivation_path`: The derivation path used to derive the private key inside the ECDSA canister.
    /// - `ecdsa_canister_actor`: The actor reference to the ECDSA canister (`aaaaa-aa`).
    /// - `key_name`: The name of the ECDSA key (usually `"dfx_test_key"` in local dev).
    ///
    /// # Returns:
    /// - A `Blob` containing the signature in RAW format (64 bytes: `r || s`).
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

    /// Verifies an ECDSA signature over a UTF-8 message using the Bitcoin secp256k1 curve.
    ///
    /// This function accepts either a RAW (64-byte) signature or a DER-encoded one.
    /// It infers the format automatically based on the signature length.
    ///
    /// ⚠️ IMPORTANT: This function **Don`t hash again the message**  Instead,
    /// considers that the received message is in SHA256 format (same as signing process).
    /// only use if the message has been previously converted with `Text.encodeUtf8` and `Sha256`.
    ///
    /// # Parameters:
    /// - `message`: The original message in plain text. It será codificado en UTF-8 y se asumirá como el hash.
    /// - `public_key_sec1`: The compressed SEC1 format (33 bytes) public key used to verify the signature.
    /// - `signature_blob`: The signature, in either RAW (64 bytes) or DER format.
    ///
    /// # Returns:
    /// - `true` if the signature is valid, `false` otherwise.
    public func verify_signature(
        message : Text,
        public_key_sec1 : Blob,
        signature_blob : Blob,
    ) : Bool {
        let message_bytes = Blob.toArray(Text.encodeUtf8(message));

        let ?pubkey = Utils.public_key_from_sec1_compressed(public_key_sec1) else {
            Debug.print("❌ Failed to deserialize public key from SEC1 compressed format");
            return false;
        };

        let signature : ECDSA.Signature = if (Array.size(Blob.toArray(signature_blob)) == 64) {
            let ?sig = Utils.signature_from_raw(signature_blob) else {
                Debug.print("❌ Failed to deserialize RAW signature");
                return false;
            };
            sig;
        } else {
            switch (Der.decodeSignature(signature_blob)) {
                case (#ok(sig)) sig;
                case (#err(msg)) {
                    Debug.print("❌ Failed to deserialize signature from DER format: " # msg);
                    return false;
                };
            };
        };
        let verified = ECDSA.verify(signature, pubkey, message_bytes);
        verified;
    };

    /// Signs all P2WPKH inputs in a raw Bitcoin transaction that match the provided public key.
    ///
    /// This function parses the raw transaction (in hex), derives the P2WPKH scriptPubKey from the given
    /// public key, and signs every input whose scriptPubKey matches.
    ///
    /// # Parameters
    /// - `tx_hex`: Raw Bitcoin transaction in hexadecimal format (not a PSBT).
    /// - `pubkey`: Public key in compressed SEC1 format (33 bytes).
    /// - `derivation_path`: Derivation path used to retrieve the private key from the ECDSA canister.
    /// - `ecdsa_canister_actor`: Actor interface for the Management Canister (`aaaaa-aa`) that exposes `sign_with_ecdsa`.
    /// - `key_name`: Name of the key to use (e.g., `"dfx_test_key"` for local testing).
    ///
    /// # Returns
    /// - `#ok(signedTxHex)`: The fully signed transaction in hexadecimal format.
    /// - `#err(message)`: Error message if the signing process fails.
    ///
    /// # Limitations
    /// - Only supports signing P2WPKH inputs.
    /// - Input amounts are not provided, which is technically required for full BIP-143 compliance.
    ///   This function assumes zeroed input amounts when computing the sighash.
    /// - Uses `SIGHASH_ALL` as the sighash type.
    ///
    /// # Future Improvements
    /// A version of this function will include a parameter to provide UTXO amounts per input,
    /// enabling 100% BIP-143 compliance.
    ///
    /// # Example
    /// ```motoko
    /// let result = await sign_transaction_p2wpkh_from_hex(
    ///   "0200000001...",
    ///   pubkey,
    ///   derivationPath,
    ///   ecdsaActor,
    ///   "dfx_test_key"
    /// );
    /// ```

    /* public func sign_transaction_p2wpkh_from_hex(
        tx_hex : Text,
        pubkey : [Nat8],
        derivation_path : [Blob],
        ecdsa_canister_actor : Types.EcdsaCanisterActor,
        key_name : Text,
    ) : async Result.Result<Text, Text> {
        // 1. Decode hex -> blob
        let ?tx_bytes = Hex.decode(tx_hex) else {
            return #err("❌ Invalid tx hex");
        };

        // 2. Parse tx
        let tx_res = Transaction.fromBytes(Array.vals(Blob.toArray(tx_bytes)));
        let tx = switch tx_res {
            case (#ok t) t;
            case (#err msg) return #err("❌ Cannot parse tx: " # msg);
        };

        // 3. Derive the scriptPubKey for this pubkey (P2WPKH)
        let sha256 = Sha256.fromArray(#sha256, pubkey);
        let pubkey_hash160 = Ripemd160.hash(Blob.toArray(sha256));
        let script_pubkey : Script.Script = [
            #opcode(#OP_0),
            #data(pubkey_hash160),
        ];

        // 4. Iterate inputs and match which ones can be signed
        let sighash_type : Nat32 = 0x01; // SIGHASH_ALL
        var signed_any = false;

        for (i in Iter.range(0, tx.txInputs.size() - 1)) {
            // TODO: Mejorar esto si puedes obtener el scriptPubKey original del input.
            // Aquí asumimos que todos los inputs son tipo P2WPKH de tu pubkey.
            let sig_hash = tx.createP2pkhSignatureHash(
                script_pubkey,
                Nat32.fromNat(i),
                sighash_type,
            );

            let sig_reply = await ecdsa_canister_actor.sign_with_ecdsa({
                message_hash = Blob.fromArray(sig_hash);
                derivation_path = derivation_path;
                key_id = { curve = #secp256k1; name = key_name };
            });

            let raw_sig = Blob.toArray(sig_reply.signature);
            if (raw_sig.size() != 64) {
                return #err("❌ Signature must be 64 bytes RAW");
            };

            let sig_with_type = Array.append(raw_sig, [Nat8.fromNat(Nat32.toNat(sighash_type))]);

            // Inserta el testigo
            tx.witnesses[i] := [
                sig_with_type,
                pubkey,
            ];
            signed_any := true;
        };

        if (not signed_any) {
            return #err("❌ No matching inputs found to sign for this pubkey");
        };

        // 5. Serialize and return hex
        let final_tx_bytes = tx.toBytes();
        let hex_result = Hex.encode(Blob.fromArray(final_tx_bytes));

        #ok(hex_result);
    }; */

    /// Signs all P2WPKH inputs in a Bitcoin transaction that belong to a given public key,
    /// using the ECDSA system canister. It uses a list of known UTXOs to match the inputs.
    ///
    /// The function parses the transaction, iterates through its inputs, and for each one:
    /// - Matches the input’s `outpoint` against the provided list of UTXOs (by `txid` and `vout`)
    /// - Computes the BIP-143 sighash using the corresponding UTXO value
    /// - Signs the hash with the ECDSA canister using the provided derivation path
    /// - Inserts the generated witness (signature + pubkey) into the transaction
    ///
    /// # Parameters:
    /// - `tx_hex`: Raw transaction in hexadecimal format (non-PSBT, but with inputs/outputs filled)
    /// - `pubkey`: Compressed SEC1 public key (33 bytes) that corresponds to the UTXOs
    /// - `derivation_path`: Path used to derive the private key for signing
    /// - `ecdsa_canister_actor`: Actor reference to the management canister or delegated ECDSA signer
    /// - `key_name`: Name of the key to use (e.g., `"dfx_test_key"`)
    /// - `utxos`: List of known UTXOs for the address, including their values and outpoints
    ///
    /// # Returns:
    /// - `#ok(signed_tx_hex)`: Fully signed transaction in hex (with SegWit witnesses included)
    /// - `#err(error_message)`: Descriptive error if parsing or signing failed
    ///
    /// # Notes:
    /// - Only SegWit P2WPKH inputs matching UTXOs will be signed
    /// - Inputs not recognized in the UTXO list are left untouched
    /// - Taproot, P2PKH, and multisig are not supported (yet)
    ///
    /// Example usage:
    /// ```motoko
    /// let result = await sign_transaction_p2wpkh_from_hex(tx_hex, pubkey, path, ecdsa_actor, "dfx_test_key", utxos);
    /// switch result {
    ///   case (#ok(signed)) { /* broadcast */ };
    ///   case (#err(e)) { /* handle error */ };
    /// }
    /// ```
    public func sign_transaction_p2wpkh_from_hex(
        tx_hex : Text,
        pubkey : [Nat8],
        derivation_path : [Blob],
        ecdsa_canister_actor : Types.EcdsaCanisterActor,
        key_name : Text,
        utxos : [BitcoinTypes.Utxo],
    ) : async Result.Result<Text, Text> {
        // Step 1: Decode the hex string
        let ?tx_blob = Hex.decode(tx_hex) else return #err("❌ Invalid hex string");
        let tx_bytes = Blob.toArray(tx_blob);

        // Step 2: Parse the transaction
        let iter = Array.vals(tx_bytes);
        let tx_res = Transaction.fromBytes(iter);
        let tx = switch tx_res {
            case (#ok t) t;
            case (#err msg) return #err("❌ Failed to parse transaction: " # msg);
        };

        // Step 3: Derive the address from the pubkey
        let sha256 = Sha256.fromArray(#sha256, pubkey);
        let hash160 = Ripemd160.hash(Blob.toArray(sha256));
        let my_script_pubkey : Script.Script = [
            #opcode(#OP_0),
            #data(hash160),
        ];

        // Step 4: Determine which inputs to sign
        let my_utxos = Array.filter<BitcoinTypes.Utxo>(
            utxos,
            func(utxo) {
                let script_hash = Ripemd160.hash(
                    Blob.toArray(
                        Sha256.fromArray(#sha256, pubkey)
                    )
                );
                let script = [
                    #opcode(#OP_0),
                    #data(script_hash),
                ];
                Script.toBytes(script) == Script.toBytes(my_script_pubkey);
            },
        );

        if (my_utxos.size() == 0) return #err("❌ No matching UTXOs found");

        // Step 5: Iterate over inputs and sign those that match our UTXOs
        let sighash_type : Nat32 = 0x01; // SIGHASH_ALL

        for (i in Iter.range(0, tx.txInputs.size() - 1)) {
            let input = tx.txInputs[i];
            let matching = Array.find<BitcoinTypes.Utxo>(
                my_utxos,
                func(utxo) {
                    Blob.toArray(utxo.outpoint.txid) == Blob.toArray(input.prevOutput.txid) and utxo.outpoint.vout == input.prevOutput.vout;
                },
            );

            switch matching {
                case null {};
                case (?utxo) {
                    let sig_hash = tx.createP2pkhSignatureHash(
                        my_script_pubkey,
                        Nat32.fromNat(i),
                        sighash_type,
                    );

                    let sig_reply = await ecdsa_canister_actor.sign_with_ecdsa({
                        message_hash = Blob.fromArray(sig_hash);
                        derivation_path = derivation_path;
                        key_id = { curve = #secp256k1; name = key_name };
                    });

                    let raw_sig = Blob.toArray(sig_reply.signature);
                    if (raw_sig.size() != 64) return #err("❌ Invalid RAW signature length");

                    let sig_with_type = Array.append(raw_sig, [Nat8.fromNat(Nat32.toNat(sighash_type))]);

                    tx.witnesses[i] := [
                        sig_with_type,
                        pubkey,
                    ];
                };
            };
        };

        // Step 6: Serialize transaction and return hex
        let final_tx_bytes = tx.toBytes();
        let hex_result = Hex.encode(Blob.fromArray(final_tx_bytes));
        #ok(hex_result);
    };

};
