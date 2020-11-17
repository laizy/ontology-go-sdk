package main

import (
	"fmt"
	"math"
	"math/big"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/account"
	utils2 "github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/core/utils"
)

type MarketInfo struct {
	Name string
	Decimal int
	Insurance string
	FTokenAddress string
}

var Markets = func () map[string]*MarketInfo {
	market:= make(map[string]*MarketInfo)
	market["ONTD"] = &MarketInfo {
		Name: "ONTD",
		Decimal : 9,
		Insurance : "dcba8e32ab89a0e27d4350118bfd482f531c02cb",
		FTokenAddress: "cc8ca2a1e10ff02feb6313b3fa347d08a5981b22",
	}
	market["WING"] = &MarketInfo {
		Name: "WING",
		Decimal : 9,
		Insurance : "b03b5a4f4ea36d6a8ab25a01a41874b6261ca5d6",
		FTokenAddress: "b2fc52315b9b1f1dca93720109aa7270511ced7c",
	}

	return market
}()

func main() {
	osdk := sdk.NewOntologySdk()
	url :=  "http://dappnode2.ont.io:20336"

	res := RedeemUnderlyingFromIssurance(osdk, LoadAccount(), Markets["WING"], 950, 1).Send(url)

	fmt.Printf("%v \n", res)
}

func RedeemUnderlyingFromIssurance(osdk *sdk.OntologySdk, acct *account.Account, market *MarketInfo,
amt, div int64) * sdk.SignedTx {
	amount := big.NewInt(amt)
	amount = amount.Mul(amount, big.NewInt(int64(math.Pow10(market.Decimal))))
	amount = amount.Div(amount, big.NewInt(div))
	
	contract, err := common.AddressFromHexString(market.Insurance)
	checkerr(err)
	return osdk.WasmVM.InvokeWasm(contract, "redeemUnderlying",
		[]interface{}{acct.Address, amount}).SignTx(acct)
}

func checkerr(err error) {
	if err != nil {
		panic(err)
	}
}

func NewAccountFromWIF(wif string) (*account.Account, error) {
	prvkey, err := keypair.GetP256KeyPairFromWIF([]byte(wif))
	if err != nil {
		return nil, fmt.Errorf("GetP256KeyPairFromWIF error:%s", err)
	}
	pubKey := prvkey.Public()
	address := types.AddressFromPubKey(pubKey)

	return &account.Account{
		PrivateKey: prvkey,
		PublicKey:  pubKey,
		Address:    address,
		SigScheme:  signature.SHA256withECDSA,
	}, nil
}
