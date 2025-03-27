import { test } "mo:test/async";
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import BitcoinAddressGenerator "../src/lib";
import Types "../src/Types";

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

    public func runTests() : async () {
        await test("deterministic P2PKH address", test_deterministic_p2pkh_address);
        await test("deterministic P2WPKH address", test_deterministic_p2wpkh_address);
    };
};
