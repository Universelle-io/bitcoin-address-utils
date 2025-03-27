import Nat8 "mo:base/Nat8";
import Char "mo:base/Char";
import Iter "mo:base/Iter";
import Array "mo:base/Array";
import Text "mo:base/Text";

module {
    public func toHex(bytes : [Nat8]) : Text {
        let hexChars = Text.toIter("0123456789abcdef");
        let hexArray = Iter.toArray(hexChars);

        let result : [Char] = Array.flatten(
            Array.map(
                bytes,
                func(b : Nat8) : [Char] {
                    let hi = b / 16;
                    let lo = b % 16;
                    [hexArray[Nat8.toNat(hi)], hexArray[Nat8.toNat(lo)]];
                },
            )
        );

        Text.fromIter(Iter.fromArray(result));
    };
};
