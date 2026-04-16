# gowpa

WPA supplicant interface for Go — scan Wi-Fi networks and connect using wpa_cli or D-Bus/wpadbus.

## Installation

```bash
go get github.com/sonnt85/gowpa
```

## Features

- Scan for nearby Wi-Fi networks (SSIDs) using `iwlist` or `wpa_cli`
- Connect to a WPA/WPA2 network by SSID and password
- Query currently connected network on a given interface
- D-Bus-based connection manager for event-driven connect flow
- D-Bus-based scan manager that returns full BSS info (BSSID, frequency, signal, key management)
- Global singleton managers (`ConnectManager`, `ScanManager`) for quick use
- IPv4/IPv6 address retrieval after connection

## Usage

```go
import "github.com/sonnt85/gowpa"

// Quick scan (returns SSID list)
ssids := gowpa.Scan("wlan0")
fmt.Println(ssids)

// Quick connect
err := gowpa.Connect("MySSID", "mypassword", "wlan0")
if err != nil {
    log.Fatal(err)
}

// Query current connection
ssid, err := gowpa.GetCurrentConnect("wlan0")
fmt.Println("Connected to:", ssid)

// D-Bus scan manager (full BSS details)
sm := gowpa.NewScanManager("wlan0")
bssList, err := sm.Scan()
for _, bss := range bssList {
    fmt.Printf("SSID: %s  Signal: %d  Freq: %d\n", bss.SSID, bss.Signal, bss.Frequency)
}

// D-Bus connect manager (event-driven)
cm := gowpa.NewConnectManager("wlan0")
info, err := cm.Connect("MySSID", "mypassword", 30*time.Second)
fmt.Printf("Connected: %s  IP4: %s\n", info.SSID, info.IP4)
```

## API

### Types
- `BSS` — scanned access point: `BSSID`, `SSID`, `Signal`, `Frequency`, `KeyMgmt`, `Privacy`, `WPS`, `Mode`, `Age`
- `ConnectionInfo` — result of a successful connect: `NetInterface`, `SSID`, `IP4`, `IP6`

### Package-level Functions
- `Scan(ifaces ...string) []string` — scan via `iwlist`, return SSIDs sorted by signal
- `Scan1(ifaces ...string) []string` — scan via `wpa_cli scan_results`
- `Connect(ssid, password string, ifaces ...string) error` — connect via `wpa_cli`
- `GetCurrentConnect(iface string) (string, error)` — return currently connected SSID

### connectManager
- `NewConnectManager(netInterface string) *connectManager`
- `(*connectManager).Connect(ssid, password string, timeout Duration) (ConnectionInfo, error)` — D-Bus connect with timeout

### scanManager
- `NewScanManager(netInterface string) *scanManager`
- `(*scanManager).Scan() ([]BSS, error)` — D-Bus scan, return BSS list

### Globals
- `ConnectManager` — default `*connectManager` for `wlan0`
- `ScanManager` — default `*scanManager` for `wlan0`

## Author

**sonnt85** — [thanhson.rf@gmail.com](mailto:thanhson.rf@gmail.com)

## License

MIT License - see [LICENSE](LICENSE) for details.
