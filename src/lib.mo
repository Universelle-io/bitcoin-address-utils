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
import Sha256 "mo:sha2/Sha256";
import Result "mo:base/Result";
import Iter "mo:base/Iter";
import Nat32 "mo:base/Nat32";
import Buffer "mo:base/Buffer";
import Nat "mo:base/Nat";
import ECDSA "mo:bitcoin/ecdsa/Ecdsa";
import EcdsaTypes "mo:bitcoin/ecdsa/Types";
import Der "mo:bitcoin/ecdsa/Der";
import Script "mo:bitcoin/bitcoin/Script";
import Transaction "./bitcoin/Transaction";
import Witness "mo:bitcoin/bitcoin/Witness";
import Hex "mo:base16/Base16";

import Utils "./Utils";
import DebugUtils "DebugUtils";
import Types "Types";
import P2WPKH "./bitcoin/P2WPKH";

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
        public_key_bytes : [Nat8], // Debe ser comprimida
    ) : Text {
        if (public_key_bytes.size() != 33) {
            Debug.trap("❌ public_key_to_p2wpkh_address: Requires a compressed public key (33 bytes), got " # Nat.toText(public_key_bytes.size()));
        };

        let sec1_key : EcdsaTypes.Sec1PublicKey = (public_key_bytes, CURVE);

        Debug.print("🔑 Deriving P2WPKH address from compressed key (hex): " # DebugUtils.toHex(public_key_bytes));
        switch (P2WPKH.deriveAddress(network, sec1_key)) {
            case (#ok(addr)) {
                Debug.print("✅ Derived P2WPKH address: " # addr);
                addr;
            };
            case (#err(msg)) {
                Debug.trap("❌ Failed to derive P2WPKH address: " # msg);
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

    /// Signs a P2PKH transaction provided as a hexadecimal string using the ECDSA canister.
    /// Assumes all inputs are spending outputs controlled by the provided public key.
    ///
    /// # Parameters:
    /// - `tx_hex`: The raw transaction encoded as a hexadecimal string.
    /// - `pubkey`: The compressed public key (`[Nat8]`) corresponding to the P2PKH address being spent from.
    /// - `derivation_path`: The derivation path used for signing with the ECDSA canister.
    /// - `ecdsa_canister_actor`: The actor interface for the ECDSA canister.
    /// - `key_name`: The name of the ECDSA key to use for signing.
    /// - `utxos`: The list of UTXOs being spent by the transaction (currently unused in this P2PKH signing logic, but kept for signature consistency).
    ///
    /// # Returns:
    /// A `Result.Result` containing the signed transaction as a hexadecimal string (`#ok`) or an error message (`#err`).
    public func sign_transaction_p2pkh_from_hex(
        tx_hex : Text,
        pubkey : [Nat8], // The public key controlling the inputs
        derivation_path : [Blob],
        ecdsa_canister_actor : Types.EcdsaCanisterActor,
        key_name : Text,
    ) : async Result.Result<Text, Text> {

        // 1. Decodificar la transacción
        let ?tx_blob = Hex.decode(tx_hex) else {
            Debug.print("❌ Invalid hex string for transaction");
            return #err("Invalid hex string for transaction");
        };
        let tx_bytes = Blob.toArray(tx_blob);
        let iter = Array.vals(tx_bytes);

        // 2. Parsear la transacción
        let tx_res = Transaction.fromBytes(iter);
        let tx = switch tx_res {
            case (#ok t) t;
            case (#err msg) {
                Debug.print("❌ Failed to parse transaction: " # msg);
                return #err("Failed to parse transaction: " # msg);
            };
        };
        Debug.print("📄 Parsed transaction successfully. Inputs: " # Nat.toText(tx.txInputs.size()));

        // 3. Derivar el ScriptPubKey P2PKH desde la clave pública proporcionada
        // Este es el script de los outputs que estamos gastando.
        let pubkey_hash = Ripemd160.hash(Blob.toArray(Sha256.fromArray(#sha256, pubkey)));
        let script_pub_key : Script.Script = [
            #opcode(#OP_DUP),
            #opcode(#OP_HASH160),
            #data(pubkey_hash),
            #opcode(#OP_EQUALVERIFY),
            #opcode(#OP_CHECKSIG),
        ];
        // Debug.print("📜 Derived scriptPubKey: " # Script.scriptToText(script_pub_key)); // Asumiendo una función scriptToText

        // 4. Iterar por los inputs, firmar y construir los scriptSigs
        // Usamos un Buffer para recolectar los scriptSigs calculados
        let scriptSigsBuffer = Buffer.Buffer<Script.Script>(tx.txInputs.size());

        for (i in Iter.range(0, tx.txInputs.size() - 1)) {
            let input_index = Nat32.fromNat(i); // Índice actual como Nat32
            Debug.print("✍️  Signing input " # Nat.toText(i));

            // 4a. Crear el hash de firma (SIGHASH_ALL por defecto)
            let sighash_bytes : [Nat8] = tx.createP2pkhSignatureHash(
                script_pub_key, // El scriptPubKey del output que este input está gastando
                input_index,
                BitcoinTypes.SIGHASH_ALL,
            );
            let sighash_blob = Blob.fromArray(sighash_bytes);
            // Debug.print("🔑 Sighash (hex) for input " # Nat.toText(i) # ": " # DebugUtils.toHex(sighash_bytes)); // Asumiendo DebugUtils.toHex

            // 4b. Llamar al canister ECDSA para firmar el hash
            // Adaptar la estructura de EcdsaKeyId si es diferente en tu `Types`
            let key_id : Types.EcdsaKeyId = {
                curve = #secp256k1;
                name = key_name;
            };
            let sign_request : Types.SignWithECDSA = {
                message_hash = sighash_blob;
                derivation_path = derivation_path;
                key_id = key_id;
            };

            // Realizar la llamada asíncrona
            let sign_response = await ecdsa_canister_actor.sign_with_ecdsa(sign_request);
            let signature_blob = sign_response.signature;

            // 4c. Formatear la firma: DER encoding + SIGHASH_ALL byte
            let encoded_signature_der_blob = Der.encodeSignature(signature_blob);

            let der_signature_bytes : [Nat8] = Blob.toArray(encoded_signature_der_blob);

            // Añadir el byte SIGHASH_ALL al final de la firma DER
            let signature_with_sighash_type : [Nat8] = Array.append(
                der_signature_bytes,
                [Nat8.fromNat(Nat32.toNat(BitcoinTypes.SIGHASH_ALL))],
            );
            // Debug.print("📄 Formatted signature (hex) for input " # Nat.toText(i) # ": " # DebugUtils.toHex(signature_with_sighash_type));

            // 4d. Construir el ScriptSig: <firma_formateada> <clave_publica>
            let script_sig : Script.Script = [
                #data(signature_with_sighash_type), // La firma DER + SIGHASH_ALL
                #data(pubkey) // La clave pública que corresponde al scriptPubKey
            ];
            // Debug.print("📜 Constructed scriptSig for input " # Nat.toText(i));

            // Añadir el scriptSig calculado al buffer
            scriptSigsBuffer.add(script_sig);
        };

        // 5. Actualizar los inputs de la transacción con los scriptSigs calculados
        let final_script_sigs = Buffer.toArray(scriptSigsBuffer);

        // Comprobación de seguridad: debemos tener tantos scriptSigs como inputs
        if (final_script_sigs.size() != tx.txInputs.size()) {
            let error_msg = "Internal error: Mismatch between input count ("
            # Nat.toText(tx.txInputs.size())
            # ") and signature count ("
            # Nat.toText(final_script_sigs.size())
            # ")";
            Debug.print("❌ " # error_msg);
            return #err(error_msg);
        };

        // Asignar cada scriptSig a su input correspondiente.
        // Esto modifica el objeto 'tx' directamente si TxInput.script es mutable ('var').
        // Si TxInput.script no es mutable, necesitarías crear nuevos TxInput y luego una nueva Transaction.
        // La librería motoko-bitcoin parece usar campos mutables para esto en sus funciones de firma.
        for (i in Iter.range(0, tx.txInputs.size() - 1)) {
            // Asumiendo que tx.txInputs[i].script es mutable (var)
            tx.txInputs[i].script := final_script_sigs[i];
        };
        Debug.print("✅ All inputs updated with scriptSigs.");

        // 6. Serializar la transacción firmada a bytes
        let signed_tx_bytes : [Nat8] = tx.toBytes();

        // 7. Codificar a hexadecimal y devolver
        let signed_tx_hex = Hex.encode(Blob.fromArray(signed_tx_bytes));
        Debug.print("✅ Signed transaction (hex): " # signed_tx_hex);

        return #ok(signed_tx_hex);
    };

    /// Signs a P2WPKH transaction provided as a hexadecimal string using the ECDSA canister.
    /// Assumes all inputs are native P2WPKH spending outputs controlled by the provided public key.
    /// The provided UTXOs array MUST match the transaction inputs exactly.
    ///
    /// # Parameters:
    /// - `tx_hex`: The raw transaction encoded as a hexadecimal string.
    /// - `pubkey`: The compressed public key (`[Nat8]`, 33 bytes) corresponding to the P2WPKH address being spent from.
    /// - `derivation_path`: The derivation path used for signing with the ECDSA canister.
    /// - `ecdsa_canister_actor`: The actor interface for the ECDSA canister.
    /// - `key_name`: The name of the ECDSA key to use for signing.
    /// - `utxos`: An array of UTXOs being spent. Must be in the same order as the transaction inputs,
    ///            and contain the correct `value` (amount) for each input.
    ///
    /// # Returns:
    /// A `Result.Result` containing the signed transaction (including witness data)
    /// as a hexadecimal string (`#ok`) or an error message (`#err`).
    public func sign_transaction_p2wpkh_from_hex(
        tx_hex : Text,
        pubkey : [Nat8], // Compressed pubkey (33 bytes usually)
        derivation_path : [Blob],
        ecdsa_canister_actor : Types.EcdsaCanisterActor,
        key_name : Text,
        utxos : [BitcoinTypes.Utxo] // Crucial for input values!
    ) : async Result.Result<Text, Text> {

        // Basic validation on pubkey format
        if (pubkey.size() != 33) {
            Debug.print("❌ Invalid public key size for P2WPKH (expected 33 bytes compressed): " # Nat.toText(pubkey.size()));
            // Puedes comentar Debug.print si no lo necesitas
            return #err("Invalid public key size for P2WPKH (expected 33 bytes compressed)");
        };

        // 1. Decodificar la transacción
        let ?tx_blob = Hex.decode(tx_hex) else {
            Debug.print("❌ Invalid hex string for transaction");
            return #err("Invalid hex string for transaction");
        };
        let tx_bytes = Blob.toArray(tx_blob);
        let iter = Array.vals(tx_bytes);

        // 2. Parsear la transacción usando TU Transaction.mo modificado
        let tx_res = Transaction.fromBytes(iter);
        let tx : Transaction.Transaction = switch tx_res {
            // Especificar tipo por claridad
            case (#ok t) t;
            case (#err msg) {
                Debug.print("❌ Failed to parse transaction: " # msg);
                return #err("Failed to parse transaction: " # msg);
            };
        };
        Debug.print("📄 Parsed transaction successfully. Inputs: " # Nat.toText(tx.txInputs.size()));

        // 3. Validar Inputs vs UTXOs
        if (tx.txInputs.size() != utxos.size()) {
            let error_msg = "Mismatch between transaction inputs ("
            # Nat.toText(tx.txInputs.size())
            # ") and provided UTXOs ("
            # Nat.toText(utxos.size())
            # ")";
            Debug.print("❌ " # error_msg);
            return #err(error_msg);
        };

        // Pre-calculate PubKey Hash
        let pubkey_hash = Ripemd160.hash(Blob.toArray(Sha256.fromArray(#sha256, pubkey)));
        if (pubkey_hash.size() != 20) {
            return #err("Internal error: Invalid pubkey hash size");
        };

        // Construct the scriptCode required for P2WPKH sighash
        let p2pkh_script_instructions : Script.Script = [
            #opcode(#OP_DUP),
            #opcode(#OP_HASH160),
            #data(pubkey_hash), // pubkey_hash es [Nat8] de 20 bytes
            #opcode(#OP_EQUALVERIFY),
            #opcode(#OP_CHECKSIG),
        ];

        // Serializa el script. Script.toBytes() antepondrá automáticamente el VarInt 0x19.
        let scriptCode : [Nat8] = Script.toBytes(p2pkh_script_instructions);
        Debug.print("ScriptCode generado por Script.toBytes (hex): " # debug_show (Blob.fromArray(scriptCode)));

        // Buffer para los datos witness
        let witnessDataBuffer = Buffer.Buffer<Witness.Witness>(tx.txInputs.size());

        // 4. Iterar por los inputs, calcular sighash, firmar, construir witness
        for (i in Iter.range(0, tx.txInputs.size() - 1)) {
            let input_index : Nat32 = Nat32.fromNat(i); // Usar Nat32 consistentemente
            let tx_input = tx.txInputs[i];
            let utxo = utxos[i];
            Debug.print("✍️  Processing input " # Nat.toText(i));

            // 4a. Sanity check: UTXO vs Input
            if (Blob.equal(tx_input.prevOutput.txid, utxo.outpoint.txid) == false or tx_input.prevOutput.vout != utxo.outpoint.vout) {
                let error_msg = "Input " # Nat.toText(i) # " outpoint does not match provided UTXO";
                Debug.print("❌ " # error_msg);
                return #err(error_msg);
            };

            let utxo_value : Nat64 = utxo.value;

            // 4b. <<< ¡¡LLAMADA AL NUEVO MÉTODO!! >>>
            // Llama al método que implementaste en Transaction.mo
            // Pasamos 'tx' como el 'self' explícito que tu método espera actualmente.
            let sighash_bytes_res : Result.Result<[Nat8], Text> = tx.createP2wpkhSignatureHash(
                // self: Transaction, // El 'tx' actual actúa como 'self'
                // txInputIndex : Nat32,
                // scriptCode : [Nat8],
                // value : Nat64,
                // sigHashType : Types.SighashType,
                tx, // <--- Pasando tx como el 'self' explícito
                input_index,
                scriptCode,
                utxo_value,
                BitcoinTypes.SIGHASH_ALL // O el tipo que necesites
            );
            // <<< FIN LLAMADA >>>

            // -- Manejo del resultado del sighash --
            let sighash_bytes = switch (sighash_bytes_res) {
                case (#ok bytes) bytes;
                case (#err e) {
                    Debug.print("❌ Failed to create SegWit sighash for input " # Nat.toText(i) # ": " # e);
                    return #err("Failed to create SegWit sighash: " # e);
                };
            };
            let sighash_blob = Blob.fromArray(sighash_bytes);

            // 4c. Firmar con ECDSA Canister (sin cambios)
            let key_id : Types.EcdsaKeyId = {
                curve = #secp256k1;
                name = key_name;
            };
            let sign_request : Types.SignWithECDSA = {
                message_hash = sighash_blob;
                derivation_path = derivation_path;
                key_id = key_id;
            };
            // Assuming sign_with_ecdsa returns 'async SignResponse' directly and traps on error
            let sign_response : Types.SignWithECDSAReply = await ecdsa_canister_actor.sign_with_ecdsa(sign_request);
            // If the above line completes without trapping, we have the signature.
            let signature_blob : Blob = sign_response.signature;
            // Remove the switch statement as it's no longer needed.
            // Error handling for signing failures must be managed differently (e.g., assuming it won't fail
            // or using try/catch if Motoko adds better support for catching traps across async calls).
            Debug.print("✅ Signature received for input " # Nat.toText(i));

            // 4d. Formatear Firma (DER + SIGHASH_ALL byte) (sin cambios)
            // 4d. Formatear Firma (DER + SIGHASH_ALL byte)
            // Asumiendo que Der.encodeSignature devuelve Blob y atrapa en caso de error.
            let encoded_signature_der_blob : Blob = Der.encodeSignature(signature_blob);
            let der_signature_bytes : [Nat8] = Blob.toArray(encoded_signature_der_blob);

            // Añadir el byte SIGHASH_ALL al final de la firma DER
            // Array.append funciona aquí porque ambos argumentos son [Nat8]
            let signature_with_sighash_type : [Nat8] = Array.append<Nat8>(
                der_signature_bytes,
                // Nat8.fromNat devuelve Nat8, por lo que [Nat8.fromNat(...)] es [Nat8]
                [Nat8.fromNat(Nat32.toNat(BitcoinTypes.SIGHASH_ALL))],
            );

            // 4e. Construir Witness Stack (sin cambios)
            let witness_stack : Witness.Witness = [
                signature_with_sighash_type,
                pubkey,
            ];
            witnessDataBuffer.add(witness_stack);

            // 4f. Asegurar scriptSig vacío (sin cambios)
            tx.txInputs[i].script := [];

        }; // Fin del bucle for

        // 5. Actualizar los witnesses en la transacción (sin cambios)
        let final_witness_data = Buffer.toArray(witnessDataBuffer);
        if (final_witness_data.size() != tx.witnesses.size()) {
            return #err("Internal error: Witness count mismatch");
        };
        for (i in Iter.range(0, final_witness_data.size() - 1)) {
            tx.witnesses[i] := final_witness_data[i];
        };
        Debug.print("✅ All witness data updated in the transaction.");

        // 6. Serializar la transacción firmada (sin cambios)
        let signed_tx_bytes : [Nat8] = tx.toBytes();

        // 7. Codificar a hexadecimal y devolver (sin cambios)
        let signed_tx_hex = Hex.encode(Blob.fromArray(signed_tx_bytes));
        Debug.print("🎉 P2WPKH Transaction signed successfully! Hex prefix: " # debug_show (signed_tx_hex));

        return #ok(signed_tx_hex);
    };

};
