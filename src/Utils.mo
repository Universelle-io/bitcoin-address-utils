import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Array "mo:base/Array";
import PublicKey "mo:bitcoin/ecdsa/Publickey";
import EcdsaTypes "mo:bitcoin/ecdsa/Types";
import Curves "mo:bitcoin/ec/Curves";
import Common "mo:bitcoin/Common";

module {
    public func public_key_from_sec1_compressed(sec1 : Blob) : ?EcdsaTypes.PublicKey {
        let curve = Curves.secp256k1;
        let result = PublicKey.decode(#sec1(Blob.toArray(sec1), curve));
        switch result {
            case (#ok(pk)) ?pk;
            case (#err(msg)) {
                Debug.print("❌ PublicKey decode error: " # msg);
                null;
            };
        };
    };

    public func signature_from_raw(blob : Blob) : ?EcdsaTypes.Signature {
        let bytes = Blob.toArray(blob);
        if (bytes.size() != 64) return null;

        let r_bytes = Array.subArray(bytes, 0, 32);
        let s_bytes = Array.subArray(bytes, 32, 32);

        let r = Common.readBE256(r_bytes, 0);
        let s = Common.readBE256(s_bytes, 0);

        ?{ r; s };
    }

};
