import { test } "mo:test/async";
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Text "mo:base/Text";
import Nat "mo:base/Nat";
import Array "mo:base/Array";
import Der "mo:bitcoin/ecdsa/Der";
import Sha256 "mo:sha2/Sha256";
import BitcoinAddressGenerator "../src/lib";
import Types "../src/Types";
import DebugUtils "../src/DebugUtils";

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

    func testnet_p2wpkh_address_for_funding() : async () {
        let principal = Principal.fromText(test_principal);
        let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
        let EcdsaActor : Types.EcdsaCanisterActor = actor ("aaaaa-aa");

        let testnet_address_p2wpkh = await BitcoinAddressGenerator.get_p2wpkh_address(
            path,
            #Testnet,
            EcdsaActor,
            "dfx_test_key",
        );

        let testnet_address_p2pkh = await BitcoinAddressGenerator.get_p2pkh_address(
            path,
            #Testnet,
            EcdsaActor,
            "dfx_test_key",
        );

        Debug.print("📬 Testnet P2WPKH Address to fund: " # testnet_address_p2wpkh);
        Debug.print("📬 Testnet P2PKH Address to fund: " # testnet_address_p2pkh);
    };

    public func runTests() : async () {
        await test("deterministic P2PKH address", test_deterministic_p2pkh_address);
        await test("deterministic P2WPKH address", test_deterministic_p2wpkh_address);
        await test("signature verification", test_signature_verification);
        await test("testnet P2WPKH address for funding", testnet_p2wpkh_address_for_funding);
    };

    public func run() : async () {
        await testnet_p2wpkh_address_for_funding()
    };
};
