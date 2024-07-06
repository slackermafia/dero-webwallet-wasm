# build wasm module containing go functions
GOOS=js GOARCH=wasm go build -o dero_wallet.wasm main.go
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
sha512sum ./build/dero_wallet.wasm > ./build/sha512sums.txt
