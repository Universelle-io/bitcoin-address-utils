import { test } "mo:test/async";
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Text "mo:base/Text";
import Array "mo:base/Array";
import Sha256 "mo:sha2/Sha256";
import BitcoinAddressGenerator "../src/lib";
import Types "../src/Types";
import DebugUtils "../src/DebugUtils";
import BitcoinApi "../src/BitcoinApi";
import Transaction "mo:bitcoin/bitcoin/Transaction";
import Address "mo:bitcoin/bitcoin/Address";
import Bitcoin "mo:bitcoin/bitcoin/Bitcoin";
import BitcoinTypes "mo:bitcoin/bitcoin/Types";
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

    public func get_utxos(address : ?Text) : async [BitcoinApi.Utxo] {
        let efective_address = switch address {
            case (?a) a;
            case (_) {
                "bcrt1qncwqapkpapl8d00mgwt2s6cqdfsvz7cyr4ehk8";
            };
        };
        Debug.print("🔍 Buscando UTXOs para dirección: " # efective_address);
        let utxos_response = await BitcoinApi.get_utxos(#Regtest, efective_address);
        Debug.print("🔍 UTXOs encontrados: " # debug_show (utxos_response.utxos.size()));
        let utxos = utxos_response.utxos;
        utxos;
    };

    public func get_balance(address : ?Text) : async BitcoinApi.Satoshi {
        let efective_address = switch address {
            case (?a) a;
            case (_) {
                "bcrt1qncwqapkpapl8d00mgwt2s6cqdfsvz7cyr4ehk8";
            };
        };
        Debug.print("🔍 Buscando UTXOs para dirección: " # efective_address);
        let balance_response = await BitcoinApi.get_balance(#Regtest, efective_address);
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
        let destinations : [(BitcoinTypes.Address, Nat64)] = [(btc_address, amount)];
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

    public func test_consolidate_utxos_p2wpkh() : async () {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");
        let key_name = "dfx_test_key";

        // Obtener dirección P2WPKH
        let address = await BitcoinAddressGenerator.get_p2wpkh_address(
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
        let destinations : [(BitcoinTypes.Address, Nat64)] = [(btc_address, amount)];
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
        let signed_result = await BitcoinAddressGenerator.sign_transaction_p2wpkh_from_hex(
            tx_hex,
            pubkey_sec1,
            path,
            EcdsaActor,
            key_name,
            utxos,
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

    public func runTests() : async () {
        await test("deterministic P2PKH address", test_deterministic_p2pkh_address);
        await test("deterministic P2WPKH address", test_deterministic_p2wpkh_address);
        await test("signature verification", test_signature_verification);
    };

    public func run() : async () {

    };
};
