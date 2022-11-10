# copy wasm_exec.js helper to nft web app public folder
# cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ../dero-nft-trade/public/
# wget https://github.com/tinygo-org/tinygo/blob/v0.26.0/targets/wasm_exec.js
# build wasm module containing go functions
GOOS=js GOARCH=wasm go build -o ./build/dero_wallet.wasm #../dero-nft-trade/public/dero_wallet.wasm
# tinygo build -o main.wasm -target wasm ./main.go
cp ./build/dero_wallet.wasm ../dero-nft-trade/public
sha512sum ./build/dero_wallet.wasm > ./build/sha512sums.txt