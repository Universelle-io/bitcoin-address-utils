import { test } "mo:test/async";
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Text "mo:base/Text";
import Array "mo:base/Array";
import Result "mo:base/Result";
import Nat "mo:base/Nat";
import Nat64 "mo:base/Nat64";
import Sha256 "mo:sha2/Sha256";
import BitcoinAddressGenerator "../src/lib";
import Types "../src/Types";
import DebugUtils "../src/DebugUtils";
import BitcoinApi "../src/BitcoinApi";
import Transaction "../src/bitcoin/Transaction";
import Address "../src/bitcoin/Address";
import Bitcoin "../src/bitcoin/Bitcoin";
import BitcoinTypes "../src//bitcoin/Types";
import Witness "mo:bitcoin/bitcoin/Witness";
import Hex "mo:base16/Base16";

actor {
    let test_principal = "jdzlb-sc4ik-hdkdr-nhzda-3m4tn-2znax-fxlfm-w2mhf-e5a3l-yyrce-cqe";

    func test_deterministic_p2pkh_address() : async () {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");

        let addr1 = await BitcoinAddressGenerator.get_p2pkh_address(
            path,
            #Mainnet,
            EcdsaActor,
            "dfx_test_key",
        );
        let addr2 = await BitcoinAddressGenerator.get_p2pkh_address(
            path,
            #Mainnet,
            EcdsaActor,
            "dfx_test_key",
        );

        Debug.print("🏁 P2PKH 1: " # addr1);
        Debug.print("🏁 P2PKH 2: " # addr2);
        assert (addr1 == addr2);
    };

    func test_deterministic_p2wpkh_address() : async () {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");

        let addr1 = await BitcoinAddressGenerator.get_p2wpkh_address(
            path,
            #Mainnet,
            EcdsaActor,
            "dfx_test_key",
        );
        let addr2 = await BitcoinAddressGenerator.get_p2wpkh_address(
            path,
            #Mainnet,
            EcdsaActor,
            "dfx_test_key",
        );

        Debug.print("🏁 P2WPKH 1: " # addr1);
        Debug.print("🏁 P2WPKH 2: " # addr2);
        assert (addr1 == addr2);
    };

    func test_signature_verification() : async () {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");
        let key_name = "dfx_test_key";

        let message = "hello world";
        Debug.print("🔐 Original message: " # message);

        let signature = await BitcoinAddressGenerator.sign_message(
            message,
            path,
            EcdsaActor,
            key_name,
        );
        Debug.print("📩 Raw Signature: " # debug_show (signature));

        let pubkey_reply = await EcdsaActor.ecdsa_public_key({
            canister_id = null;
            derivation_path = path;
            key_id = { curve = #secp256k1; name = key_name };
        });
        let pubkey_sec1 = pubkey_reply.public_key;
        Debug.print("🔑 Public Key (SEC1 compressed): " # debug_show (pubkey_sec1));

        let verified = BitcoinAddressGenerator.verify_signature(
            message,
            pubkey_sec1,
            signature,
        );

        Debug.print("✅ Signature verified: " # debug_show (verified));
        Debug.print("🧪 Derivation path (hex): " # DebugUtils.toHex(Blob.toArray(path[0])));
        Debug.print("🧪 Message hash (hex): " # DebugUtils.toHex(Blob.toArray(Sha256.fromArray(#sha256, Blob.toArray(Text.encodeUtf8(message))))));

        assert (verified == true);
    };

    public func get_testnet_address_p2pkh() : async Text {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");

        await BitcoinAddressGenerator.get_p2pkh_address(
            path,
            #Regtest,
            EcdsaActor,
            "dfx_test_key",
        );
    };

    public func get_testnet_address_p2wpkh() : async Text {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");

        await BitcoinAddressGenerator.get_p2wpkh_address(
            path,
            #Regtest,
            EcdsaActor,
            "dfx_test_key",
        );
    };

    public func get_utxos(address : Text) : async [BitcoinApi.Utxo] {
        Debug.print("🔍 Buscando UTXOs para dirección: " # address);
        let utxos_response = await BitcoinApi.get_utxos(#Regtest, address);
        Debug.print("🔍 UTXOs encontrados: " # debug_show (utxos_response.utxos.size()));
        let utxos = utxos_response.utxos;
        utxos;
    };

    public func get_balance(address : Text) : async BitcoinApi.Satoshi {
        Debug.print("🔍 Buscando UTXOs para dirección: " # address);
        let balance_response = await BitcoinApi.get_balance(#Regtest, address);
        balance_response;
    };

    public func test_consolidate_utxos_p2pkh() : async () {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");
        let key_name = "dfx_test_key";

        // Obtener dirección P2WPKH
        let address = await BitcoinAddressGenerator.get_p2pkh_address(
            path,
            #Regtest,
            EcdsaActor,
            key_name,
        );
        Debug.print("📬 Dirección P2WPKH para consolidar: " # address);

        // Obtener pubkey en formato SEC1 comprimido
        let pubkey_reply = await EcdsaActor.ecdsa_public_key({
            canister_id = null;
            derivation_path = path;
            key_id = { curve = #secp256k1; name = key_name };
        });
        let pubkey_sec1 = Blob.toArray(pubkey_reply.public_key);

        // Obtener UTXOs
        Debug.print("🔍 Buscando UTXOs...");
        let utxos_response = await BitcoinApi.get_utxos(#Regtest, address);
        let utxos = utxos_response.utxos;
        assert (utxos.size() > 0);
        // Calcular total
        let total : Nat64 = Array.foldLeft(
            utxos,
            0 : Nat64,
            func(acc : Nat64, utxo : BitcoinApi.Utxo) : Nat64 {
                acc + utxo.value;
            },
        );

        let fee : Nat64 = 10000;
        let amount : Nat64 = total - fee;

        // Parsear dirección
        let parsed_address_res = Address.addressFromText(address);
        let btc_address : BitcoinTypes.Address = switch (parsed_address_res) {
            case (#ok(a)) a;
            case (#err(e)) {
                Debug.print("❌ Dirección inválida: " # e);
                assert false;
                #p2pkh("");
            };
        };

        // Construir transacción consolidando todos los utxos a sí misma
        let destinations : [(BitcoinTypes.Address, BitcoinTypes.Satoshi)] = [(btc_address, amount)];
        let tx_result = Bitcoin.buildTransaction(
            2,
            utxos,
            destinations,
            btc_address,
            fee,
        );

        let tx : Transaction.Transaction = switch tx_result {
            case (#ok(t)) t;
            case (#err(e)) {
                Debug.print("❌ Error al construir la tx: " # e);
                assert false;
                Transaction.Transaction(2, [], [], Array.init<Witness.Witness>(0, Witness.EMPTY_WITNESS), 0);
            };
        };

        let tx_hex = Hex.encode(Blob.fromArray(tx.toBytes()));
        Debug.print("📤 Transacción (hex) antes de firmar: " # tx_hex);

        // Firmar la transacción
        let signed_result = await BitcoinAddressGenerator.sign_transaction_p2pkh_from_hex(
            tx_hex,
            pubkey_sec1,
            path,
            EcdsaActor,
            key_name,
        );

        Debug.print("🔏 Firmando transacción...");

        let tx_bytes : [Nat8] = switch signed_result {
            case (#ok(signed_tx)) {
                Debug.print("✅ Transacción firmada (hex): " # signed_tx);
                assert (signed_tx.size() > 0);

                switch (Hex.decode(signed_tx)) {
                    case (?blob) Blob.toArray(blob);
                    case null {
                        Debug.print("❌ No se pudo decodificar el hex.");
                        assert false;
                        [];
                    };
                };
            };
            case (#err(e)) {
                Debug.print("❌ Error al firmar: " # e);
                assert false;
                [];
            };
        };

        await BitcoinApi.send_transaction(#Regtest, tx_bytes);

    };

    public func test_consolidate_utxos_p2wpkh() : async Result.Result<(Text, Text), Text> {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");
        let key_name = "dfx_test_key"; // Use appropriate key name

        // Obtener dirección P2WPKH
        // get_p2wpkh_address returns Text, assuming it traps on internal error
        let address = await BitcoinAddressGenerator.get_p2wpkh_address(
            path,
            #Regtest,
            EcdsaActor,
            key_name,
        );
        Debug.print("📬 Dirección P2WPKH para consolidar: " # address);

        Debug.print("🔑 Obteniendo clave pública ECDSA...");

        // Asumiendo que ecdsa_public_key devuelve el récord directamente y atrapa en error
        let pubkey_reply : { public_key : Blob; chain_code : Blob } = await EcdsaActor.ecdsa_public_key({
            canister_id = null;
            derivation_path = path;
            key_id = { curve = #secp256k1; name = key_name };
        });
        // Si la línea anterior se completa sin atrapar, tenemos la respuesta. No se necesita switch.
        Debug.print("✅ Clave pública obtenida.");

        let pubkey_sec1 = Blob.toArray(pubkey_reply.public_key);

        // Añadir validación para asegurar que es comprimida (necesario para P2WPKH)
        if (pubkey_sec1.size() != 33) {
            Debug.print("❌ Error: La clave pública obtenida no está comprimida (33 bytes)");
            // Ahora que la función devuelve Result, usamos return #err
            return #err("Retrieved public key is not compressed (33 bytes)");
        };

        // Obtener UTXOs
        Debug.print("🔍 Buscando UTXOs...");
        // Assuming BitcoinApi.get_utxos returns Result
        let utxos_response = await BitcoinApi.get_utxos(#Regtest, address);
        let utxos = utxos_response.utxos;

        if (utxos.size() == 0) {
            Debug.print("ℹ️ No UTXOs found for address " # address # ". Nothing to consolidate.");
            return #err("No UTXOs found to consolidate"); // Or maybe #ok with a specific message?
        };
        Debug.print("💰 Found " # Nat.toText(utxos.size()) # " UTXOs.");

        // Calcular total
        let total : Nat64 = Array.foldLeft<BitcoinApi.Utxo, Nat64>(
            // Use correct Utxo type
            utxos,
            0 : Nat64,
            func(acc, utxo) { acc + utxo.value },
        );
        Debug.print("Σ Total value: " # Nat64.toText(total) # " satoshis");

        let fee : Nat64 = 10000; // Example fee
        if (total <= fee) {
            return #err("Total value (" # Nat64.toText(total) # ") is not enough to cover fee (" # Nat64.toText(fee) # ")");
        };
        let amount : Nat64 = total - fee;

        // Parsear dirección
        let parsed_address_res = Address.addressFromText(address);
        let btc_address : BitcoinTypes.Address = switch (parsed_address_res) {
            case (#ok(a)) a;
            case (#err(e)) {
                // Should not happen if get_p2wpkh_address worked, but handle defensively
                Debug.print("❌ Error parsing own address: " # e);
                return #err("Error parsing own address: " # e);
            };
        };

        // Construir transacción
        let destinations : [(BitcoinTypes.Address, Nat64)] = [(btc_address, amount)];
        // Ensure utxos type matches what buildTransaction expects ([BitcoinTypes.Utxo]?)
        // If BitcoinApi.Utxo != BitcoinTypes.Utxo, mapping might be needed. Assuming compatible for now.
        let tx_result = Bitcoin.buildTransaction(
            2, // version
            utxos,
            destinations,
            btc_address,
            fee,
        );

        let tx : Transaction.Transaction = switch tx_result {
            case (#ok(t)) t;
            case (#err(e)) {
                Debug.print("❌ Error al construir la tx: " # e);
                return #err("Error building transaction: " # e);
            };
        };

        let tx_hex = Hex.encode(Blob.fromArray(tx.toBytes()));
        Debug.print("🛠️ Transacción construida (hex): " # tx_hex); // Or use debug_show

        // Firmar la transacción
        Debug.print("🔏 Firmando transacción...");
        let signed_result = await BitcoinAddressGenerator.sign_transaction_p2wpkh_from_hex(
            tx_hex,
            pubkey_sec1, // Must be compressed
            path,
            EcdsaActor,
            key_name,
            utxos, // Pass UTXOs for value calculation during signing
        );

        // Procesar resultado de la firma
        switch (signed_result) {
            case (#ok(signed_tx_hex)) {
                Debug.print("✅ Transacción firmada (hex): " # signed_tx_hex); // Or debug_show

                // --- Obtener bytes y TXID ---
                let ?tx_blob = Hex.decode(signed_tx_hex) else {
                    Debug.print("❌ Error crítico: No se pudo decodificar el hex de la tx firmada.");
                    return #err("Failed to decode signed transaction hex");
                };
                let tx_bytes = Blob.toArray(tx_blob);

                if (tx_bytes.size() == 0) {
                    return #err("Signed transaction decoded to empty bytes");
                };

                // Re-parsear para obtener TXID (costoso pero necesario si solo tenemos hex)
                let iter = Array.vals(tx_bytes);
                let tx_obj_res = Transaction.fromBytes(iter);
                let parsed_tx = switch (tx_obj_res) {
                    case (#ok t) t;
                    case (#err e) {
                        Debug.print("❌ Error crítico: No se pudo re-parsear la tx firmada: " # e);
                        return #err("Failed to re-parse signed transaction: " # e);
                    };
                };
                let txid_bytes = parsed_tx.txid(); // Llama al método txid() en el objeto
                let txid_hex = Hex.encode(Blob.fromArray(txid_bytes));
                Debug.print("🆔 TXID: " # txid_hex);
                // --- Fin obtener bytes y TXID ---

                // Enviar transacción
                Debug.print("🚀 Enviando transacción...");
                // Consider adding error handling for send_transaction if it returns Result
                await BitcoinApi.send_transaction(#Regtest, tx_bytes);
                Debug.print("✅ Transacción enviada (esperando confirmación).");

                // Devolver (#ok (txid, signed_hex))
                #ok((txid_hex, signed_tx_hex));

            };
            case (#err(sign_err)) {
                Debug.print("❌ Error al firmar la transacción: " # sign_err);
                #err("Transaction signing failed: " # sign_err); // Devolver error
            };
        };
    };

    public func runTests() : async () {
        await test("deterministic P2PKH address", test_deterministic_p2pkh_address);
        await test("deterministic P2WPKH address", test_deterministic_p2wpkh_address);
        await test("signature verification", test_signature_verification);
    };

    public func run() : async () {

    };
};
