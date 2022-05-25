package main

import (
	"context"
	"fmt"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/ipfs-cluster/api"
	sdk "hlm-ipfs/ipfs-clutser-go-sdk/sdk/client"
)
func main()  {
	cl, err := sdk.NewDefaultClient(&sdk.Config{
		Host:     "10.41.1.3",
		Port:     "9094",
	})
	if err != nil {
		panic(err)
	}
	id,err:=cl.ID(context.TODO())
	if err != nil {
		panic(err)
	}
	fmt.Println(id)
	hash, err := cid.Decode("QmZCLMSHcVfFjYFzwTd4Nq9EUto2zzY6U6SPBU7DypGhzs")
	if err != nil {
		panic(err)
	}
	pinOut,err:=cl.Pin(context.TODO(),api.NewCid(hash),api.PinOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Println(pinOut)
}