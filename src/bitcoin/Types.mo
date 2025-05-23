module {
  // A single unit of Bitcoin.
  public type Satoshi = Nat64;

  // The type of Bitcoin network.
  public type Network = {
    #Mainnet;
    #Regtest;
    #Testnet;
  };

  // A reference to a transaction output.
  public type OutPoint = {
    txid : Blob;
    vout : Nat32;
  };

  // An unspent transaction output.
  public type Utxo = {
    outpoint : OutPoint;
    value : Satoshi;
    height : Nat32;
  };

  public type SighashType = Nat32;
  public let SIGHASH_ALL : SighashType = 0x01;
  public let SIGHASH_NONE : SighashType = 0x02;
  public let SIGHASH_SINGLE : SighashType = 0x03;
  public let SIGHASH_ANYONECANPAY : SighashType = 0x80;

  public type BitcoinPrivateKey = {
    network : Network;
    key : Nat;
    compressedPublicKey : Bool;
  };

  public type P2PkhAddress = Text;
  public type P2WPkhAddress = Text;
  public type P2WShAddress = Text;
  public type P2trKeyAddress = Text;
  public type P2trScriptAddress = Text;

  public type Address = {
    #p2pkh : P2PkhAddress;
    #p2wpkh : P2WPkhAddress;
    #p2wsh : P2WShAddress;
    #p2tr_key : P2trKeyAddress;
    #p2tr_script : P2trScriptAddress;
  };

  public type BitcoinSendTransactionError = {
    #MalformedTransaction : Text;
    #QueueFull : Text;
    #TemporarilyUnavailable : Text;
    #Unknown : Text;
  };
};
