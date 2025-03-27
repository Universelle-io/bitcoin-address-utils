import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Buffer "mo:base/Buffer";
import Result "mo:base/Result";
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

};
