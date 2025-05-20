import ExperimentalCycles "mo:base/ExperimentalCycles";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import BitcoinTypes "bitcoin/Types";

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
    public let GET_BALANCE_COST_CYCLES : Cycles = 100_000_000;
    public let GET_UTXOS_COST_CYCLES : Cycles = 10_000_000_000;
    public let GET_CURRENT_FEE_PERCENTILES_COST_CYCLES : Cycles = 100_000_000;
    public let SEND_TRANSACTION_BASE_COST_CYCLES : Cycles = 5_000_000_000;
    public let SEND_TRANSACTION_COST_CYCLES_PER_BYTE : Cycles = 20_000_000;

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

    //public func send_bitcoin_transaction(network : BitcoinTypes.Network, transaction : [Nat8]) : async Result.Result<(), BitcoinTypes.BitcoinSendTransactionError> {
    //    let transaction_fee = SEND_TRANSACTION_BASE_COST_CYCLES + transaction.size() * SEND_TRANSACTION_COST_CYCLES_PER_BYTE;
    //
    //    // ExperimentalCycles.add<system>(transaction_fee); // Mantenemos la lógica de ciclos (comentada) consistente
    //
    //    try {
    //        // Llama a la función del management canister
    //        await management_canister_actor.bitcoin_send_transaction({
    //            network;
    //            transaction;
    //        });
    //        // Si la llamada await no falla (no hace trap), es éxito
    //        return #Ok;
    //    } catch (e) {
    //        // Si la llamada await falla, entra en el bloque catch
    //        // Analizamos el error 'e' para devolver un BitcoinError apropiado
    //        // El objeto 'e' de Motoko no siempre es fácil de inspeccionar,
    //        // a menudo se usa Debug.show para obtener una representación textual.
    //
    //        // Intentamos clasificar el error basándonos en patrones comunes en el mensaje
    //        // Nota: Esto es una aproximación; la robustez depende de los mensajes de error reales.
    //        if (Text.contains(e, "malformed transaction") or Text.contains(error_text, "invalid transaction")) {
    //            return #Err(#MalformedTransaction(error_text));
    //        } else if (Text.contains(error_text, "Queue full")) {
    //            return #Err(#QueueFull(error_text));
    //        } else if (Text.contains(error_text, "temporarily unavailable")) {
    //            return #Err(#TemporarilyUnavailable(error_text));
    //        } else {
    //            // Si no coincide con los patrones conocidos, se clasifica como desconocido
    //            return #Err(#Unknown(error_text));
    //        };
    //    };
    //};
};
