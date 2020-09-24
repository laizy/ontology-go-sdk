package ontology_go_sdk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-go-sdk/client"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/core/utils"
)

const defaultGasPrice = 2500
const defaultGasLimit = 1000000

type TxBuilder struct {
	tx *types.MutableTransaction
}

func NewBuilder() *TxBuilder {
	tx := &types.MutableTransaction{
		GasPrice: defaultGasPrice,
		GasLimit: defaultGasLimit,
		Nonce:    uint32(time.Now().Unix()),
		Sigs:     nil,
	}
	return &TxBuilder{
		tx: tx,
	}
}

func (self *TxBuilder) SetGasLimit(limit uint64) *TxBuilder {
	self.tx.GasLimit = limit
	return self
}

func (self *TxBuilder) SetGasPrice(price uint64) *TxBuilder {
	self.tx.GasPrice = price
	return self
}

func (self *TxBuilder) SetPayer(payer common.Address) *TxBuilder {
	self.tx.Payer = payer
	return self
}

func (self *TxBuilder) invokeWasm(code []byte) *TxBuilder {
	self.tx.TxType = types.InvokeWasm
	self.tx.Payload = &payload.InvokeCode{
		Code: code,
	}

	return self
}

func (self *TxBuilder) invokeNeo(code []byte) *TxBuilder {
	self.tx.TxType = types.InvokeNeo
	self.tx.Payload = &payload.InvokeCode{
		Code: code,
	}

	return self
}

type SignedTx struct {
	tx *types.MutableTransaction
}

func (self *SignedTx) PreExecute(url string) string {
	imt, err := self.tx.IntoImmutable()
	checkerr(err)
	res, err := SendTransaction(url, imt, true)
	checkerr(err)
	return string(res)
}

func (self *SignedTx) Send(url string) string {
	imt, err := self.tx.IntoImmutable()
	checkerr(err)
	res, err := SendTransaction(url, imt, false)
	checkerr(err)
	return string(res)
}

func (self *TxBuilder) SignTx(signer *account.Account) *SignedTx {
	tx := self.tx
	if self.tx.Payer == common.ADDRESS_EMPTY {
		self.tx.Payer = signer.Address
	}
	txHash := tx.Hash()
	sigData, err := signature.Sign(signer, txHash.ToArray())
	checkerr(err)
	tx.Sigs = append(tx.Sigs, types.Sig{
		PubKeys: []keypair.PublicKey{signer.PubKey()},
		M:       1,
		SigData: [][]byte{sigData},
	})

	return &SignedTx{
		tx: tx,
	}
}

func checkerr(err error) {
	if err != nil {
		panic(err)
	}
}

func (this *WasmVMContract) InvokeWasm(contract common.Address, method string, param []interface{}) *TxBuilder {
	params := append([]interface{}{method}, param...)
	code, err := utils.BuildWasmVMInvokeCode(contract, params)
	checkerr(err)

	return NewBuilder().invokeWasm(code)
}

func SendTransaction(url string, tx *types.Transaction, isPreExec bool) ([]byte, error) {
	txData := hex.EncodeToString(common.SerializeToBytes(tx))
	params := []interface{}{txData}
	if isPreExec {
		params = append(params, 1)
	}
	return SendRpcRequest(url, "0", client.RPC_SEND_TRANSACTION, params)
}

func SendRpcRequest(url, qid, method string, params []interface{}) ([]byte, error) {
	rpcReq := &client.JsonRpcRequest{
		Version: client.JSON_RPC_VERSION,
		Id:      qid,
		Method:  method,
		Params:  params,
	}
	data, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("JsonRpcRequest json.Marsha error:%s", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rpc response body error:%s", err)
	}

	return body, nil
}
