import ExperimentalCycles "mo:base/ExperimentalCycles";


module {
    public type Cycles = Nat;

    public type Satoshi = Nat64;

    public type Network = {
        #Mainnet;
        #Testnet;
        #Regtest;
    };

    public type BitcoinAddress = Text;

    public type OutPoint = {
        txid : Blob;
        vout : Nat32;
    };

    public type Utxo = {
        outpoint : OutPoint;
        value : Satoshi;
        height : Nat32;
    };

    public type BlockHash = [Nat8];

    public type Page = [Nat8];

    public type GetUtxosResponse = {
        utxos : [Utxo];
        tip_block_hash : BlockHash;
        tip_height : Nat32;
        next_page : ?Page;
    };
    
    public type MillisatoshiPerVByte = Nat64;
    
    public type GetBalanceRequest = {
        address : BitcoinAddress;
        network : Network;
        min_confirmations : ?Nat32;
    };
    
    public type UtxosFilter = {
        #MinConfirmations : Nat32;
        #Page : Page;
    };

    public type GetUtxosRequest = {
        address : BitcoinAddress;
        network : Network;
        filter : ?UtxosFilter;
    };
    
    public type GetCurrentFeePercentilesRequest = {
        network : Network;
    };
    
    
    public type SendTransactionRequest = {
        transaction : [Nat8];
        network : Network;
    };

    // The fees for the various Bitcoin endpoints.
    let GET_BALANCE_COST_CYCLES : Cycles = 100_000_000;
    let GET_UTXOS_COST_CYCLES : Cycles = 10_000_000_000;
    let GET_CURRENT_FEE_PERCENTILES_COST_CYCLES : Cycles = 100_000_000;
    let SEND_TRANSACTION_BASE_COST_CYCLES : Cycles = 5_000_000_000;
    let SEND_TRANSACTION_COST_CYCLES_PER_BYTE : Cycles = 20_000_000;

    /// Actor definition to handle interactions with the management canister.
    type ManagementCanisterActor = actor {
        bitcoin_get_balance : GetBalanceRequest -> async Satoshi;
        bitcoin_get_utxos : GetUtxosRequest -> async GetUtxosResponse;
        bitcoin_get_current_fee_percentiles : GetCurrentFeePercentilesRequest -> async [MillisatoshiPerVByte];
        bitcoin_send_transaction : SendTransactionRequest -> async ();
    };

    let management_canister_actor : ManagementCanisterActor = actor ("aaaaa-aa");

    /// Returns the balance of the given Bitcoin address.
    ///
    /// Relies on the `bitcoin_get_balance` endpoint.
    /// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_balance
    public func get_balance(network : Network, address : BitcoinAddress) : async Satoshi {
        //ExperimentalCycles.add<system>(GET_BALANCE_COST_CYCLES);
        await management_canister_actor.bitcoin_get_balance({
            address;
            network;
            min_confirmations = null;
        });
    };

    /// Returns the UTXOs of the given Bitcoin address.
    ///
    /// NOTE: Relies on the `bitcoin_get_utxos` endpoint.
    /// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_utxos
    public func get_utxos(network : Network, address : BitcoinAddress) : async GetUtxosResponse {
        //ExperimentalCycles.add<system>(GET_UTXOS_COST_CYCLES);
        await management_canister_actor.bitcoin_get_utxos({
            address;
            network;
            filter = null;
        });
    };

    /// Returns the 100 fee percentiles measured in millisatoshi/vbyte.
    /// Percentiles are computed from the last 10,000 transactions (if available).
    ///
    /// Relies on the `bitcoin_get_current_fee_percentiles` endpoint.
    /// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_current_fee_percentiles
    public func get_current_fee_percentiles(network : Network) : async [MillisatoshiPerVByte] {
        //ExperimentalCycles.add<system>(GET_CURRENT_FEE_PERCENTILES_COST_CYCLES);
        await management_canister_actor.bitcoin_get_current_fee_percentiles({
            network;
        });
    };

    /// Sends a (signed) transaction to the Bitcoin network.
    ///
    /// Relies on the `bitcoin_send_transaction` endpoint.
    /// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_send_transaction
    public func send_transaction(network : Network, transaction : [Nat8]) : async () {
        let transaction_fee = SEND_TRANSACTION_BASE_COST_CYCLES + transaction.size() * SEND_TRANSACTION_COST_CYCLES_PER_BYTE;

        //ExperimentalCycles.add<system>(transaction_fee);
        await management_canister_actor.bitcoin_send_transaction({
            network;
            transaction;
        });
    };
};
