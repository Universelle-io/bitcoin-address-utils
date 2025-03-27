module {
    public type AddressType = {
        #P2PKH;
        #P2WPKH;
        #P2TR;
    };

    public type ECDSAPublicKeyReply = {
        public_key : Blob;
        chain_code : Blob;
    };

    public type SignWithECDSAReply = {
        signature : Blob;
    };

    public type SignWithECDSA = {
        message_hash : Blob;
        derivation_path : [Blob];
        key_id : EcdsaKeyId;
    };

    type EcdsaCurve = { #secp256k1 };
    type EcdsaKeyId = {
        curve : EcdsaCurve;
        name : Text;
    };

    public type ECDSAPublicKey = {
        canister_id : ?Principal;
        derivation_path : [Blob];
        key_id : EcdsaKeyId;
    };

    public type EcdsaCanisterActor = actor {
        ecdsa_public_key : ECDSAPublicKey -> async ECDSAPublicKeyReply;
        sign_with_ecdsa : SignWithECDSA -> async SignWithECDSAReply;
    };
};
