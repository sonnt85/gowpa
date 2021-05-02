package main

import (
	"fmt"
	"os"
	"time"

	"github.com/sonnt85/gowpa"
)

func main() {

	args := os.Args[1:]
	if len(args) < 2 {
		fmt.Println("Insufficient arguments")
		return
	}
	ssid := args[0]
	password := args[1]
	gowpa.SetDebugMode()
	if conn, err := gowpa.ConnectManager.Connect(ssid, password, time.Second*60); err == nil {
		fmt.Println("Connected", conn.NetInterface, conn.SSID, conn.IP4.String(), conn.IP6.String())
	} else {
		fmt.Println(err)
	}
}
