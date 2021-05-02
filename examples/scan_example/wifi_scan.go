package main

import (
	"fmt"

	"github.com/sonnt85/gowpa"
)

func main() {
	if bssList, err := gowpa.ScanManager.Scan(); err == nil {
		for _, bss := range bssList {
			fmt.Println(bss.SSID, bss.Signal, bss.KeyMgmt)
		}
	}
}
