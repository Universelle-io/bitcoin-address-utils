#!/bin/bash

set -e

AMOUNT=200000000       # 2 BTC en satoshis
BLOCKS=101             # Número de bloques a minar tras enviar
WALLET="testwallet"
CANISTER="debug"
BITCOIN_DIR="$HOME/Library/Application Support/Bitcoin"
BITCOIN_PORT=18444

echo "🚀 Iniciando entorno regtest con bitcoind..."

# Iniciar bitcoind si no está corriendo
if ! pgrep -x "bitcoind" > /dev/null; then
  echo "📦 Iniciando bitcoind en regtest..."
  bitcoind -conf="${BITCOIN_DIR}/bitcoin.conf" -fallbackfee="0.0001" -datadir="${BITCOIN_DIR}" -rpcport=""${BITCOIN_PORT}"" -daemon
fi

# También esperar hasta que bitcoin-cli --rpcport="${BITCOIN_PORT}" responda correctamente
until bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest getblockchaininfo > /dev/null 2>&1; do
  sleep 0.5
done

echo "✅ bitcoind arrancado."

echo "📁 Verificando que la wallet '$WALLET' exista y esté cargada..."
if ! bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" getwalletinfo >/dev/null 2>&1; then
    if bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest listwallets | grep -q "$WALLET"; then
        echo "📂 Wallet encontrada pero no cargada, cargando..."
        bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest loadwallet "$WALLET"
    elif [ -d "$BITCOIN_DIR/regtest/wallets/$WALLET" ]; then
        echo "📂 Carpeta de wallet '$WALLET' ya existe, cargando manualmente..."
        bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest loadwallet "$WALLET"
    else
        echo "📂 Wallet no existe, creando..."
        bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest createwallet "$WALLET"
    fi
fi

echo "📡 Obteniendo dirección P2PKH desde el canister..."
ADDR_P2PKH=$(dfx canister call ${CANISTER} get_testnet_address_p2pkh | sed -E 's/.*"([^"]+)".*/\1/')
echo "📬 Dirección P2PKH: $ADDR_P2PKH"

echo "📡 Obteniendo dirección P2WPKH desde el canister..."
ADDR_P2WPKH=$(dfx canister call ${CANISTER} get_testnet_address_p2wpkh | sed -E 's/.*"([^"]+)".*/\1/')
echo "📬 Dirección P2WPKH: $ADDR_P2WPKH"

echo "🧪 Validando direcciones..."
bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" validateaddress "$ADDR_P2PKH" >/dev/null
bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" validateaddress "$ADDR_P2WPKH" >/dev/null

echo "💰 Comprobando balance..."
BALANCE=$(bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" getbalance)
echo "💰 Balance: $BALANCE"
if (( $(echo "$BALANCE < 2.0" | bc -l) )); then
    echo "⛏️ Fondos insuficientes. Minando bloques para generar fondos..."
    MINING_ADDR=$(bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" getnewaddress)
    bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" generatetoaddress 101 "$MINING_ADDR"
fi

echo "💸 Enviando fondos..."
P2PKH_SEND_RESPONSE=$(bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" sendtoaddress "$ADDR_P2PKH" $(bc -l <<< "$AMOUNT / 100000000"))
P2WPKH_SEND_RESPONSE=$(bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" sendtoaddress "$ADDR_P2WPKH" $(bc -l <<< "$AMOUNT / 100000000"))
echo "💸 Transacción P2PKH: $P2PKH_SEND_RESPONSE"
echo "💸 Transacción P2WPKH: $P2WPKH_SEND_RESPONSE"

echo "⛏️ Minando bloques para confirmar transacciones..."
MINING_ADDR=$(bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" getnewaddress)
bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" generatetoaddress $BLOCKS "$ADDR_P2PKH" 
bitcoin-cli --rpcport="${BITCOIN_PORT}" -regtest -rpcwallet="$WALLET" generatetoaddress $BLOCKS "$ADDR_P2WPKH" 


echo "✅ Fondos enviados y confirmados en regtest"
