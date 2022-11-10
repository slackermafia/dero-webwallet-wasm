//go:build js && wasm
// +build js,wasm

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"syscall/js"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/deroproject/derohe/walletapi/mnemonics"
)

var WalletInstances = make(map[string]*walletapi.Wallet_Memory)

func mapReturn(value interface{}, err error) interface{} {
	var _err interface{}

	if err != nil {
		_err = err.Error()
	}

	return map[string]interface{}{
		"err":   _err,
		"value": value,
	}
}

func getWallet(key string) (*walletapi.Wallet_Memory, error) {
	walletInstance := WalletInstances[key]
	if walletInstance == nil {
		return nil, fmt.Errorf(`wallet [%s] not instantiated`, key)
	}

	return walletInstance, nil
}

func getWalletInfo(wallet *walletapi.Wallet_Memory) map[string]interface{} {
	walletInfo := make(map[string]interface{})

	data := wallet.Get_Encrypted_Wallet()
	a := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(a, data)

	walletInfo["fileData"] = a.Get("buffer")
	walletInfo["address"] = wallet.GetAddress().String()
	walletInfo["seed"] = wallet.GetSeed()
	walletInfo["hexSeed"] = wallet.Get_Keys().Secret.String()
	return walletInfo
}

func CreateNewWallet(this js.Value, args []js.Value) interface{} {
	password := args[0].String()
	wallet, err := walletapi.Create_Encrypted_Wallet_Random_Memory(password)
	if err != nil {
		return mapReturn(nil, err)
	}

	walletInfo := getWalletInfo(wallet)
	return mapReturn(walletInfo, nil)
}

func RecoverWalletFromSeed(this js.Value, args []js.Value) interface{} {
	password := args[0].String()
	seed := args[1].String()

	wallet, err := walletapi.Create_Encrypted_Wallet_From_Recovery_Words_Memory(password, seed)
	if err != nil {
		return mapReturn(nil, err)
	}

	walletInfo := getWalletInfo(wallet)
	return mapReturn(walletInfo, nil)
}

func RecoverWalletFromHexSeed(this js.Value, args []js.Value) interface{} {
	password := args[0].String()
	hexSeed := args[1].String()

	var seed crypto.Key
	seedRaw, err := hex.DecodeString(hexSeed)
	if err != nil {
		return mapReturn(nil, err)
	}

	if len(seedRaw) != 32 {
		return mapReturn(nil, fmt.Errorf(`Hex seed must be 64 chars`))
	}

	copy(seed[:], seedRaw[:32])
	eSeed := new(crypto.BNRed).SetBytes(seed[:])
	wallet, err := walletapi.Create_Encrypted_Wallet_Memory(password, eSeed)
	if err != nil {
		return mapReturn(nil, err)
	}

	walletInfo := getWalletInfo(wallet)
	return mapReturn(walletInfo, nil)
}

func RecoverWalletFromDisk(this js.Value, args []js.Value) interface{} {
	password := args[0].String()
	fileData := []byte(args[1].String())

	wallet, err := walletapi.Open_Encrypted_Wallet_Memory(password, fileData)
	if err != nil {
		return mapReturn(nil, err)
	}

	walletInfo := getWalletInfo(wallet)
	return mapReturn(walletInfo, nil)
}

func CloseWallet(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	walletInstance.Close_Encrypted_Wallet()
	WalletInstances[walletKey] = nil
	return mapReturn(nil, nil)
}

func WalletGetEncryptedData(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	walletInfo := getWalletInfo(walletInstance)
	return mapReturn(walletInfo["fileData"], nil)
}

func OpenWallet(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	password := args[1].String()
	fileData := []byte(args[2].String())
	onlineMode := args[3].Bool()

	wallet, err := walletapi.Open_Encrypted_Wallet_Memory(password, fileData)
	if err != nil {
		return mapReturn(nil, err)
	}

	if onlineMode {
		if !walletapi.Connected {
			return mapReturn(nil, fmt.Errorf("walletapi not connected"))
		}

		wallet.SetNetwork(globals.IsMainnet())
		wallet.SetOnlineMode()
	}

	WalletInstances[walletKey] = wallet

	return mapReturn(nil, nil)
}

// this is a copy of w.sign() because the function is lowercase and can't be call
func walletSign(w *walletapi.Wallet_Memory) (c, s *big.Int) {
	var tmppoint bn256.G1

	tmpsecret := crypto.RandomScalar()
	tmppoint.ScalarMult(crypto.G, tmpsecret)

	keys := w.Get_Keys()
	serialize := []byte(fmt.Sprintf("%s%s", keys.Public.G1().String(), tmppoint.String()))
	c = crypto.ReducedHash(serialize)
	s = new(big.Int).Mul(c, keys.Secret.BigInt())
	s = s.Mod(s, bn256.Order)
	s = s.Add(s, tmpsecret)
	s = s.Mod(s, bn256.Order)

	return
}

func WalletRegister(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	targetLeadingZero := args[1].Int()

	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	hashRate := 0
	count := 0

	status := map[string]interface{}{
		`hr`: 0,   // hashrate
		`c`:  0,   // hastcount
		`tx`: nil, // registration payload (id and hex)
	}
	js.Global().Set("RegistrationStatus_"+walletKey, status) // reset

	add := walletInstance.Get_Keys().Public.EncodeCompressed()

	// I am not using GetRegistrationTX() function
	// I have deconstruct it to skip code and make it faster

	start := time.Now()
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go func() {
			for {
				var tx transaction.Transaction
				tx.Version = 1
				tx.TransactionType = transaction.REGISTRATION
				copy(tx.MinerAddress[:], add[:])
				c, s := walletSign(walletInstance)
				crypto.FillBytes(c, tx.C[:])
				crypto.FillBytes(s, tx.S[:])

				//tx := walletInstance.GetRegistrationTX()

				hash := tx.GetHash()

				check := 0
				for t := 0; t < targetLeadingZero; t++ {
					check += int(hash[t])
				}

				if check == 0 {
					fmt.Println(hash.String(), walletKey)
					status[`tx`] = map[string]interface{}{
						"txId":  tx.GetHash().String(),
						"txHex": hex.EncodeToString(tx.Serialize()),
					}
					js.Global().Set("RegistrationStatus_"+walletKey, status)
					break
				}

				count++
				hashRate++

				if time.Now().Add(-1 * time.Second).After(start) {
					status[`hr`] = hashRate
					status[`c`] = count
					start = time.Now()
					hashRate = 0
					js.Global().Set("RegistrationStatus_"+walletKey, status)
				}

				time.Sleep(10 * time.Millisecond)
			}
		}()
	}

	return mapReturn(nil, nil)
}

func WalletGetBalance(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	scId := args[1].String()

	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	mb, _ := walletInstance.Get_Balance_scid(crypto.HashHexToHash(scId))
	return mapReturn(mb, nil)
}

func WalletGetAddress(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	addr := walletInstance.GetAddress().String()
	return mapReturn(addr, nil)
}

func WalletGetSeed(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	seed := walletInstance.GetSeed()
	return mapReturn(seed, nil)
}

func WalletGetHexSeed(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	hexSeed := walletInstance.Get_Keys().Secret.String()
	return mapReturn(hexSeed, nil)
}

func DaemonGetTopoHeight(this js.Value, args []js.Value) interface{} {
	height := walletapi.Get_Daemon_TopoHeight()
	return mapReturn(height, nil)
}

func WalletGetTopoHeight(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	height := walletInstance.Get_TopoHeight()
	return mapReturn(height, nil)
}

func WalletGetTransfers(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	coinbase := args[1].Bool()
	in := args[2].Bool()
	out := args[3].Bool()

	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	var zeroscid crypto.Hash
	entries := walletInstance.Show_Transfers(zeroscid, coinbase, in, out, 0, 0, "", "", 0, 0)

	return mapReturn(entries, nil)
}

func WalletTransfer(this js.Value, args []js.Value) interface{} {
	asyncKey := args[0].String()
	walletKey := args[1].String()
	data := args[2].String()

	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	var params rpc.Transfer_Params
	err = json.Unmarshal([]byte(data), &params)
	if err != nil {
		return mapReturn(nil, err)
	}

	for _, t := range params.Transfers {
		_, err := t.Payload_RPC.CheckPack(transaction.PAYLOAD0_LIMIT)
		if err != nil {
			return mapReturn(nil, err)
		}
	}

	if len(params.SC_Code) >= 1 {
		if sc, err := base64.StdEncoding.DecodeString(params.SC_Code); err == nil {
			params.SC_Code = string(sc)
		}
	}

	if params.SC_Code != "" && params.SC_ID == "" {
		params.SC_RPC = append(params.SC_RPC, rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_INSTALL)})
		params.SC_RPC = append(params.SC_RPC, rpc.Argument{Name: rpc.SCCODE, DataType: rpc.DataString, Value: params.SC_Code})
	}

	if params.SC_ID != "" {
		params.SC_RPC = append(params.SC_RPC, rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)})
		params.SC_RPC = append(params.SC_RPC, rpc.Argument{Name: rpc.SCID, DataType: rpc.DataHash, Value: crypto.HashHexToHash(params.SC_ID)})
		if params.SC_Code != "" {
			params.SC_RPC = append(params.SC_RPC, rpc.Argument{Name: rpc.SCCODE, DataType: rpc.DataString, Value: params.SC_Code})
		}
	}

	// using go statement and js global because of deadlock
	// https://github.com/golang/go/issues/34478
	go func() {
		result := map[string]interface{}{}
		tx, err := walletInstance.TransferPayload0(params.Transfers, params.Ringsize, false, params.SC_RPC, params.Fees, false)
		if err != nil {
			result["err"] = err.Error()
		} else {
			result["txId"] = tx.GetHash().String()
			result["txHex"] = hex.EncodeToString(tx.Serialize())
		}

		js.Global().Set(asyncKey, result)
	}()

	return mapReturn(nil, nil)
}

func WalletSendTransaction(this js.Value, args []js.Value) interface{} {
	asyncKey := args[0].String()
	walletKey := args[1].String()
	txHex := args[2].String()

	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	txData, err := hex.DecodeString(txHex)
	if err != nil {
		return mapReturn(nil, err)
	}

	var tx transaction.Transaction
	err = tx.Deserialize(txData)
	if err != nil {
		return mapReturn(nil, err)
	}

	// using go statement and js global because of deadlock
	// https://github.com/golang/go/issues/34478
	go func() {
		result := map[string]interface{}{}
		err = walletInstance.SendTransaction(&tx)
		if err != nil {
			result["err"] = err.Error()
		}

		js.Global().Set(asyncKey, result)
	}()

	return mapReturn(nil, err)
}

func WalletIsRegistered(this js.Value, args []js.Value) interface{} {
	walletKey := args[0].String()
	walletInstance, err := getWallet(walletKey)
	if err != nil {
		return mapReturn(nil, err)
	}

	return mapReturn(walletInstance.IsRegistered(), nil)
}

func CloseAllWallets(this js.Value, args []js.Value) interface{} {
	for key, _ := range WalletInstances {
		WalletInstances[key].Close_Encrypted_Wallet()
		WalletInstances[key] = nil
	}

	return mapReturn(nil, nil)
}

func CheckSeed(this js.Value, args []js.Value) interface{} {
	seed := args[0].String()
	_, _, err := mnemonics.Words_To_Key(seed)
	if err != nil {
		return mapReturn(nil, err)
	}

	return mapReturn(nil, nil)
}

func VerifyAddress(this js.Value, args []js.Value) interface{} {
	addrString := args[0].String()
	addr, err := globals.ParseValidateAddress(addrString)
	if err != nil {
		return mapReturn(nil, err)
	}

	integrated := addr.IsIntegratedAddress()
	return mapReturn(integrated, nil)
}

func DecodeHexTransaction(this js.Value, args []js.Value) interface{} {
	txHex := args[0].String()

	data, err := hex.DecodeString(txHex)
	if err != nil {
		return mapReturn(nil, err)
	}

	var transaction transaction.Transaction
	err = transaction.Deserialize(data)
	if err != nil {
		return mapReturn(nil, err)
	}

	data, err = json.Marshal(transaction)
	if err != nil {
		return mapReturn(nil, err)
	}

	return mapReturn(string(data), nil)
}

func DaemonSetAddressAndInit(this js.Value, args []js.Value) interface{} {
	daemonEndpoint := args[0].String()

	walletapi.SetDaemonAddress(daemonEndpoint)
	if !walletapi.Connected {
		go walletapi.Keep_Connectivity()
		walletapi.Initialize_LookupTable(1, 1<<16)
	}

	return mapReturn(nil, nil)
}

func DaemonCall(this js.Value, args []js.Value) interface{} {
	asyncKey := args[0].String()
	method := args[1].String()
	data := args[2].String()

	var params interface{}
	if len(data) > 0 {
		err := json.Unmarshal([]byte(data), &params)
		if err != nil {
			return mapReturn(nil, err)
		}
	}

	go func() {
		var res interface{}
		result := map[string]interface{}{}
		err := walletapi.RPC_Client.Call(method, params, &res)
		if err != nil {
			result["err"] = err.Error()
		} else {
			result["value"] = res
		}

		js.Global().Set(asyncKey, result)
	}()

	return mapReturn(nil, nil)
}

func main() {
	/*globals.Arguments = map[string]interface{}{}
	globals.InitializeLog(os.Stdout, io.Discard)
	debug.SetGCPercent(40)*/
	//walletapi.Initialize_LookupTable(1, 1<<21)

	globals.Config = config.Testnet
	//globals.Arguments["--simulator"] = true
	//globals.Arguments["--debug"] = true

	globals.InitializeLog(os.Stdout, io.Discard)

	js.Global().Set("CreateNewWallet", js.FuncOf(CreateNewWallet))
	js.Global().Set("CloseWallet", js.FuncOf(CloseWallet))
	js.Global().Set("CloseAllWallets", js.FuncOf(CloseAllWallets))
	js.Global().Set("OpenWallet", js.FuncOf(OpenWallet))
	js.Global().Set("RecoverWalletFromSeed", js.FuncOf(RecoverWalletFromSeed))
	js.Global().Set("RecoverWalletFromHexSeed", js.FuncOf(RecoverWalletFromHexSeed))
	js.Global().Set("RecoverWalletFromDisk", js.FuncOf(RecoverWalletFromDisk))

	js.Global().Set("WalletGetEncryptedData", js.FuncOf(WalletGetEncryptedData))
	js.Global().Set("WalletGetTopoHeight", js.FuncOf(WalletGetTopoHeight))
	js.Global().Set("WalletGetAddress", js.FuncOf(WalletGetAddress))
	js.Global().Set("WalletGetBalance", js.FuncOf(WalletGetBalance))
	js.Global().Set("WalletGetSeed", js.FuncOf(WalletGetSeed))
	js.Global().Set("WalletGetHexSeed", js.FuncOf(WalletGetHexSeed))
	js.Global().Set("WalletIsRegistered", js.FuncOf(WalletIsRegistered))
	js.Global().Set("WalletTransfer", js.FuncOf(WalletTransfer))
	js.Global().Set("WalletGetTransfers", js.FuncOf(WalletGetTransfers))
	js.Global().Set("WalletSendTransaction", js.FuncOf(WalletSendTransaction))
	js.Global().Set("WalletRegister", js.FuncOf(WalletRegister)) // registration is slow - difficulty to high for browser

	js.Global().Set("DecodeHexTransaction", js.FuncOf(DecodeHexTransaction))
	js.Global().Set("VerifyAddress", js.FuncOf(VerifyAddress))
	js.Global().Set("CheckSeed", js.FuncOf(CheckSeed))
	js.Global().Set("DaemonSetAddressAndInit", js.FuncOf(DaemonSetAddressAndInit))
	js.Global().Set("DaemonCall", js.FuncOf(DaemonCall))
	js.Global().Set("DaemonGetTopoHeight", js.FuncOf(DaemonGetTopoHeight))

	// prevent function from returning, required for wasm module
	select {}
}
