import { test } "mo:test";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import BitcoinAddressGenerator "../src/Main";

// Constante común
let test_principal = "jdzlb-sc4ik-hdkdr-nhzda-3m4tn-2znax-fxlfm-w2mhf-e5a3l-yyrce-cqe";

// === TESTS SINCRÓNICOS ===

test("principal blob of anonymous should be empty", func() {
  let principal = Principal.fromText("aaaaa-aa");
  let blob = Principal.toBlob(principal);
  assert (blob.size() == 0);
});

test("derivation path only principal", func() {
  let principal = Principal.fromText(test_principal);
  let path = BitcoinAddressGenerator.get_derivation_path_from_owner(principal, null);
  assert (path.size() == 1);
});

test("derivation path with subaccount", func() {
  let principal = Principal.fromText(test_principal);
  let path = BitcoinAddressGenerator.get_derivation_path_from_owner(
    principal,
    ?Blob.fromArray([1, 2, 3, 4])
  );
  assert (path.size() == 2);
});