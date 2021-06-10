// +build !windows

package gowpa

import (
	"errors"
	"sort"
	"strconv"

	"fmt"
	"net"
	"time"

	"github.com/godbus/dbus"
	log "github.com/sirupsen/logrus"
	"github.com/sonnt85/gosutils/sexec"
	"github.com/sonnt85/gosutils/sregexp"
	"github.com/sonnt85/gosutils/sutils"
	wpa_cli "github.com/sonnt85/gowpa/internal/wpacli"
	"github.com/sonnt85/gowpa/internal/wpadbus"
	"github.com/sonnt85/snetutils"
)

type ConnectionInfo struct {
	NetInterface string
	SSID         string
	IP4          net.IP
	IP6          net.IP
}

type connectContext struct {
	phaseWaitForScanDone           bool
	phaseWaitForInterfaceConnected bool
	scanDone                       chan bool
	connectDone                    chan bool
	ip4                            net.IP
	ip6                            net.IP
	error                          error
}

type connectManager struct {
	context      *connectContext
	deadTime     time.Time
	NetInterface string
}

type BSS struct {
	BSSID     string
	SSID      string
	KeyMgmt   []string
	WPS       string
	Frequency uint16
	Signal    int16
	Age       uint32
	Mode      string
	Privacy   bool
}

type scanContext struct {
	phaseWaitForScanDone bool
	scanDone             chan bool
}

type scanManager struct {
	scanContext  *scanContext
	NetInterface string
}

var (
	ConnectManager = &connectManager{NetInterface: "wlan0"}
	ScanManager    = &scanManager{NetInterface: "wlan0"}
)

func Scan1(ifaces ...string) (ssids []string) {
	ssids = []string{}

	cmd2run := "wpa_cli scan; wpa_cli scan_results"

	if len(ifaces) != 0 {
		cmd2run = fmt.Sprintf("wpa_cli -i %s scan; wpa_cli -i %s scan_results", ifaces[0], ifaces[0])
	}
	if stdout, errstd, err := sexec.ExecCommandShell(cmd2run, time.Minute*10); err == nil {
		for _, v := range sutils.String2lines(string(stdout)) {
			//		fmt.Println(v)
			if ssid := sregexp.New(`(?:\]\s+)(.+)$`).FindStringSubmatch(v); len(ssid) != 0 {
				ssids = append(ssids, ssid[1])
			}
		}
		//		sregexp.New().FindStringSubmatch(string(stdout))
	} else {
		log.Errorf("Can not scan ssid %s", string(errstd))
	}
	return ssids
}

func Scan(ifaces ...string) (ssids []string) {
	ssids = []string{}
	iface := ""

	if len(ifaces) != 0 {
		iface = ifaces[0]
	}
	cmd2run := fmt.Sprintf("iwlist  %s scan | grep -e SSID -e Quality", iface)

	//	fmt.Println("Scanning command ", cmd2run)
	levels := []int{}
	if stdout, errstd, err := sexec.ExecCommandShell(cmd2run, time.Minute*2); err == nil {
		for _, v := range sutils.String2lines(string(stdout)) {
			//		fmt.Println(v)
			if ssid := sregexp.New(`ESSID:"(.+)"$`).FindStringSubmatch(v); len(ssid) != 0 {
				ssids = append(ssids, ssid[1])
			}

			if level := sregexp.New(`level=(-[0-9]+)$`).FindStringSubmatch(v); len(level) != 0 {
				if signal, err := strconv.Atoi(level[1]); err == nil {
					levels = append(levels, signal)
				}
			}
		}
		sort.Slice(ssids, func(i, j int) bool {
			if i < len(levels) && j < len(levels) {
				return levels[i] < levels[j]
			} else {
				return false
			}
		})
		//		sregexp.New().FindStringSubmatch(string(stdout))
	} else {
		log.Errorf("Can not scan ssid %s", string(errstd))
	}
	return ssids
}

func Connect(ssid, password string, ifaces ...string) (err error) {
	iface := ""
	if len(ifaces) != 0 {
		iface = ifaces[0]
	}
	//	cmd2run := fmt.Sprintf("iwconfig %s essid %s key s:%s", iface, ssid, password)
	cmd2run := fmt.Sprintf(`confile=/etc/wpa_supplicant/wpa_supplicant.conf; echo -e 'ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\ncountry=VN' > $confile ; wpa_passphrase '%s' '%s' >> $confile && wpa_cli -i %s reconfigure`, ssid, password, iface)
	fmt.Printf("Command connect wifi: %s", cmd2run)
	_, stderr, err := sexec.ExecCommandShell(cmd2run, time.Minute*10)
	snetutils.IpDhcpRenew(iface)
	if err == nil {
		//		snetutils.IpDhcpRenew(iface)
		return nil
	} else {
		return fmt.Errorf(string(stderr))
	}
}

func (self *connectManager) Connect(ssid string, password string, timeout time.Duration) (connectionInfo ConnectionInfo, e error) {
	self.deadTime = time.Now().Add(timeout)
	self.context = &connectContext{}
	self.context.scanDone = make(chan bool)
	self.context.connectDone = make(chan bool)
	if wpa, err := wpadbus.NewWPA(); err == nil {
		wpa.WaitForSignals(self.onSignal)
		wpa.AddSignalsObserver()
		if wpa.ReadInterface(self.NetInterface); wpa.Error == nil {
			iface := wpa.Interface
			iface.AddSignalsObserver()
			self.context.phaseWaitForScanDone = true
			go func() {
				time.Sleep(self.deadTime.Sub(time.Now()))
				self.context.scanDone <- false
				self.context.error = errors.New("timeout")
			}()
			if iface.Scan(); iface.Error == nil {
				// Wait for scan done
				if <-self.context.scanDone; self.context.error == nil {
					if iface.ReadBSSList(); iface.Error == nil {
						bssMap := make(map[string]wpadbus.BSSWPA, 0)
						for _, bss := range iface.BSSs {
							if bss.ReadSSID(); bss.Error == nil {
								bssMap[bss.SSID] = bss
								log.Debug(bss.SSID, bss.BSSID)
							} else {
								e = err
								break
							}
						}
						if e == nil {
							if bss, exists := bssMap[ssid]; exists {
								if bss.ReadSSID(); bss.Error == nil {
									if err := self.connectToBSS(&bss, iface, password); err == nil {
										// Connected, save configuration
										cli := wpa_cli.WPACli{NetInterface: self.NetInterface}
										if err := cli.SaveConfig(); err == nil {
											connectionInfo = ConnectionInfo{NetInterface: self.NetInterface, SSID: ssid,
												IP4: self.context.ip4, IP6: self.context.ip6}
										} else {
											e = err
										}
									} else {
										e = err
									}
								} else {
									e = bss.Error
								}
							} else {
								e = errors.New("ssid_not_found")
							}
						}
					} else {
						e = iface.Error
					}
				} else {
					e = self.context.error
				}
			} else {
				e = wpa.Error
			}
			iface.RemoveSignalsObserver()
		} else {
			e = wpa.Error
		}
		wpa.RemoveSignalsObserver()
		wpa.StopWaitForSignals()
	} else {
		e = err
	}
	return
}

func (self *connectManager) connectToBSS(bss *wpadbus.BSSWPA, iface *wpadbus.InterfaceWPA, password string) (e error) {
	addNetworkArgs := map[string]dbus.Variant{
		"ssid": dbus.MakeVariant(bss.SSID),
		"psk":  dbus.MakeVariant(password)}
	if iface.RemoveAllNetworks().AddNetwork(addNetworkArgs); iface.Error == nil {
		network := iface.NewNetwork
		self.context.phaseWaitForInterfaceConnected = true
		go func() {
			time.Sleep(self.deadTime.Sub(time.Now()))
			self.context.connectDone <- false
			self.context.error = errors.New("timeout")
		}()
		if network.Select(); network.Error == nil {
			if connected := <-self.context.connectDone; self.context.error == nil {
				if connected {
					if err := self.readNetAddress(); err == nil {
					} else {
						e = err
					}
				} else {
					if iface.ReadDisconnectReason(); iface.Error == nil {
						e = errors.New(fmt.Sprintf("connection_failed, reason=%d", iface.DisconnectReason))
					} else {
						e = errors.New("connection_failed")
					}
				}
			} else {
				e = self.context.error
			}
		} else {
			e = network.Error
		}
	} else {
		e = iface.Error
	}
	return
}

func (self *connectManager) onSignal(wpa *wpadbus.WPA, signal *dbus.Signal) {
	log.Debug(signal.Name, signal.Path)
	switch signal.Name {
	case "fi.w1.wpa_supplicant1.Interface.BSSAdded":
	case "fi.w1.wpa_supplicant1.Interface.BSSRemoved":
		break
	case "fi.w1.wpa_supplicant1.Interface.ScanDone":
		self.processScanDone(wpa, signal)
	case "fi.w1.wpa_supplicant1.Interface.PropertiesChanged":
		log.Debug(signal.Name, signal.Path, signal.Body)
		self.processInterfacePropertiesChanged(wpa, signal)
	default:
		log.Debug(signal.Name, signal.Path, signal.Body)
	}
}

func (self *connectManager) readNetAddress() (e error) {
	if netIface, err := net.InterfaceByName(self.NetInterface); err == nil {
		for time.Now().Before(self.deadTime) && !self.context.hasIP() {
			if addrs, err := netIface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
						if self.context.ip4 == nil {
							self.context.ip4 = ip.To4()
							continue
						}
						if self.context.ip6 == nil {
							self.context.ip6 = ip.To16()
							continue
						}
					} else {
						e = err
						return
					}
				}
			} else {
				e = err
			}
			time.Sleep(time.Millisecond * 500)
		}
		if !self.context.hasIP() {
			e = errors.New("address_not_allocated")
		}
	} else {
		e = err
	}
	return
}

func (self *connectManager) processScanDone(wpa *wpadbus.WPA, signal *dbus.Signal) {
	log.Debug("processScanDone")
	if self.context.phaseWaitForScanDone {
		self.context.phaseWaitForScanDone = false
		self.context.scanDone <- true
	}
}

func (self *connectManager) processInterfacePropertiesChanged(wpa *wpadbus.WPA, signal *dbus.Signal) {
	log.Debug("processInterfacePropertiesChanged")
	log.Debug("phaseWaitForInterfaceConnected", self.context.phaseWaitForInterfaceConnected)
	if self.context.phaseWaitForInterfaceConnected {
		if len(signal.Body) > 0 {
			properties := signal.Body[0].(map[string]dbus.Variant)
			if stateVariant, hasState := properties["State"]; hasState {
				if state, ok := stateVariant.Value().(string); ok {
					log.Debug("State", state)
					if state == "completed" {
						self.context.phaseWaitForInterfaceConnected = false
						self.context.connectDone <- true
						return
					} else if state == "disconnected" {
						//self.context.phaseWaitForInterfaceConnected = false
						//self.context.connectDone <- false
						return
					}
				}
			}
		}
	}
}

func (self *connectContext) hasIP() bool {
	return self.ip4 != nil && self.ip6 != nil
}

func NewConnectManager(netInterface string) *connectManager {
	return &connectManager{NetInterface: netInterface}
}

func (self *scanManager) Scan() (bssList []BSS, e error) {
	self.scanContext = &scanContext{}
	self.scanContext.scanDone = make(chan bool)
	if wpa, err := wpadbus.NewWPA(); err == nil {
		wpa.WaitForSignals(self.onScanSignal)
		if wpa.ReadInterface(self.NetInterface); wpa.Error == nil {
			iface := wpa.Interface
			iface.AddSignalsObserver()
			self.scanContext.phaseWaitForScanDone = true
			if iface.Scan(); iface.Error == nil {
				// Wait for scan_example done
				<-self.scanContext.scanDone
				if iface.ReadBSSList(); iface.Error == nil {
					for _, bss := range iface.BSSs {
						if bss.ReadBSSID().ReadSSID().ReadRSN().ReadMode().ReadSignal().
							ReadFrequency().ReadPrivacy().ReadAge().ReadWPS().ReadWPA(); bss.Error == nil {
							bssList = append(bssList, BSS{BSSID: bss.BSSID, SSID: bss.SSID, KeyMgmt: bss.RSNKeyMgmt, WPS: bss.WPS,
								Frequency: bss.Frequency, Privacy: bss.Privacy, Age: bss.Age, Mode: bss.Mode, Signal: bss.Signal})
						}
					}
				}
			} else {
				e = iface.Error
			}
			iface.RemoveSignalsObserver()
		} else {
			e = wpa.Error
		}
		wpa.StopWaitForSignals()
	} else {
		e = err
	}
	return
}

func (self *scanManager) onScanSignal(wpa *wpadbus.WPA, signal *dbus.Signal) {
	log.Debug(signal.Name, signal.Path)
	switch signal.Name {
	case "fi.w1.wpa_supplicant1.Interface.BSSAdded":
	case "fi.w1.wpa_supplicant1.Interface.BSSRemoved":
	case "fi.w1.wpa_supplicant1.Interface.PropertiesChanged":
		break
	case "fi.w1.wpa_supplicant1.Interface.ScanDone":
		self.processScanDone(wpa, signal)
	default:
		log.Debug(signal.Name, signal.Path, signal.Body)
	}
}

func (self *scanManager) processScanDone(wpa *wpadbus.WPA, signal *dbus.Signal) {
	log.Debug("processScanDone")
	if self.scanContext.phaseWaitForScanDone {
		self.scanContext.phaseWaitForScanDone = false
		self.scanContext.scanDone <- true
	}
}

func NewScanManager(netInterface string) *scanManager {
	return &scanManager{NetInterface: netInterface}
}
