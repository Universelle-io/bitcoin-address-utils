import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Buffer "mo:base/Buffer";
import Result "mo:base/Result";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Array "mo:base/Array";
import PublicKey "mo:bitcoin/ecdsa/Publickey";
import EcdsaTypes "mo:bitcoin/ecdsa/Types";
import Curves "mo:bitcoin/ec/Curves";
import Der "mo:bitcoin/ecdsa/Der";
import Common "mo:bitcoin/Common";

module {
    public func convertBits(input : [Nat8], fromBits : Nat32, toBits : Nat32, pad : Bool) : Result.Result<[Nat8], Text> {
        if (fromBits > 8 or toBits > 8) {
            return #err("fromBits and toBits must be <= 8");
        };

        var acc : Nat32 = 0;
        var bits : Nat32 = 0;
        let maxv : Nat32 = (1 << toBits) - 1;
        let outputBuffer = Buffer.Buffer<Nat8>(input.size());

        for (byte in input.vals()) {
            let value : Nat32 = Nat32.fromNat(Nat8.toNat(byte));
            if ((value >> fromBits) != 0) {
                return #err("Input value '" # Nat32.toText(value) # "' exceeds fromBits");
            };
            acc := (acc << fromBits) | value;
            bits += fromBits;

            while (bits >= toBits) {
                bits -= toBits;
                let outVal = (acc >> bits) & maxv;
                outputBuffer.add(Nat8.fromNat(Nat32.toNat(outVal)));
            };
        };

        if (pad and bits > 0) {
            let outVal = (acc << (toBits - bits)) & maxv;
            outputBuffer.add(Nat8.fromNat(Nat32.toNat(outVal)));
        } else if (not pad and (bits >= fromBits or ((acc << (toBits - bits)) & maxv) != 0)) {
            return #err("Incomplete encoding");
        };

        return #ok(Buffer.toArray(outputBuffer));
    };

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

    public func signature_from_der(der : Blob) : ?EcdsaTypes.Signature {
        switch (Der.decodeSignature(der)) {
            case (#ok(sig)) {
                ?sig;
            };
            case (#err(msg)) {
                Debug.print("❌ DER decode error: " # msg);
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
