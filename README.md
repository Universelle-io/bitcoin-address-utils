# Bitcoin Address Utils

This Motoko module provides utilities to generate Bitcoin P2PKH and P2WPKH addresses from public keys, derived from an "owner" and "subaccount" using the secp256k1 curve.

## Install

To install the module, use the following command:

```bash
mops add bitcoin-address-utils
```

## Usage

### 1. **Generate a P2PKH Address from a Public Key**

To generate a P2PKH address from a public key (in compressed SEC1 format), use the `public_key_to_p2pkh_address` function.

#### Example:

```motoko
import BitcoinAddressUtils "mo:bitcoin-address-utils";

let public_key_bytes: [Nat8] = ...; // Your public key in SEC1 compressed format
let network = #Mainnet; // Or use #Testnet or #Regtest depending on the network

let p2pkh_address = BitcoinAddressUtils.public_key_to_p2pkh_address(network, public_key_bytes);
Debug.print("P2PKH Address: " # p2pkh_address);
```

### 2. **Generate a P2WPKH Address from a Public Key**

Similarly, to generate a P2WPKH address from a public key, use `public_key_to_p2wpkh_address`.

#### Example:

```motoko
import BitcoinAddressUtils "mo:bitcoin-address-utils";

let public_key_bytes: [Nat8] = ...; // Your public key in SEC1 compressed format
let network = #Mainnet; // Or use #Testnet or #Regtest depending on the network

let p2wpkh_address = BitcoinAddressUtils.public_key_to_p2wpkh_address(network, public_key_bytes);
Debug.print("P2WPKH Address: " # p2wpkh_address);
```

### 3. **Obtain an Address from a Principal**

If you want to get a derived address from a `Principal` (a unique identifier in the Internet Computer network), you first need to generate the derivation path for that `Principal`.

#### Example:

```motoko
import BitcoinAddressUtils "mo:bitcoin-address-utils";
import Principal "mo:base/Principal";

// Your Principal
let owner = Principal.fromText("jdzlb-sc4ik-hdkdr-nhzda-3m4tn-2znax-fxlfm-w2mhf-e5a3l-yyrce-cqe");
let subaccount : ?Blob = null; // Optionally specify a subaccount

// Get the derivation path
let derivation_path = BitcoinAddressUtils.get_derivation_path_from_owner(owner, subaccount);

// Generate the P2PKH address
let p2pkh_address = await BitcoinAddressUtils.get_p2pkh_address(owner, derivation_path, #Mainnet, ecdsa_canister_actor, "dfx_test_key");
Debug.print("P2PKH Address from Principal: " # p2pkh_address);
```

### 4. **Tests**

You can run the tests to verify that the module is working correctly.

`mops test`

### Contributing

Feel free to open issues or submit pull requests if you want to contribute to this project.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.