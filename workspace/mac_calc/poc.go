package main

import (
	// "encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers/path"

	// "github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/router/control"
)

// |###[ SCION Path ]###
// |  CurrINF   = 0
// |  CurrHF    = 0
// |  RSV       = 0
// |  Seg0Len   = 2
// |  Seg1Len   = 4
// |  Seg2Len   = 2
// |  \InfoFields\
// |   |###[ Info Field ]###
// |   |  Flags     =
// |   |  RSV       = 0
// |   |  SegID     = 0xfc40
// |   |  Timestamp = 2024-04-25 16:27:04
// |   |###[ Info Field ]###
// |   |  Flags     =
// |   |  RSV       = 0
// |   |  SegID     = 0x7bea
// |   |  Timestamp = 2024-04-25 16:26:55
// |   |###[ Info Field ]###
// |   |  Flags     = C
// |   |  RSV       = 0
// |   |  SegID     = 0xbcb6
// |   |  Timestamp = 2024-04-25 16:27:04
// |  \HopFields \
// |   |###[ Hop field ]###
// |   |  Flags     =
// |   |  ExpTime   = Relative: 21600.0 seconds
// |   |  ConsIngress= 1
// |   |  ConsEgress= 0
// |   |  MAC       = 0xf614cc47b032				<---- this is the MAC we want to calculate
// |   |###[ Hop field ]###
// |   |  Flags     =
// |   |  ExpTime   = Relative: 21600.0 seconds
// |   |  ConsIngress= 0
// |   |  ConsEgress= 24
// |   |  MAC       = 0x9bb8224511e6
// |   |###[ Hop field ]###
// |   |  Flags     =
// |   |  ExpTime   = Relative: 21600.0 seconds
// |   |  ConsIngress= 21
// |   |  ConsEgress= 0
// |   |  MAC       = 0xe3e01d266d39
// |   |###[ Hop field ]###
// |   |  Flags     =
// |   |  ExpTime   = Relative: 21600.0 seconds
// |   |  ConsIngress= 16
// |   |  ConsEgress= 8
// |   |  MAC       = 0x5a293ef89e22
// |   |###[ Hop field ]###
// |   |  Flags     =
// |   |  ExpTime   = Relative: 21600.0 seconds
// |   |  ConsIngress= 8
// |   |  ConsEgress= 27
// |   |  MAC       = 0xff3b80787ef0
// |   |###[ Hop field ]###
// |   |  Flags     =
// |   |  ExpTime   = Relative: 21600.0 seconds
// |   |  ConsIngress= 0
// |   |  ConsEgress= 10
// |   |  MAC       = 0xaa4ed0e8a0a9
// |   |###[ Hop field ]###
// |   |  Flags     =
// |   |  ExpTime   = Relative: 21600.0 seconds
// |   |  ConsIngress= 0
// |   |  ConsEgress= 21
// |   |  MAC       = 0x8fc0d7d9fa4f
// |   |###[ Hop field ]###
// |   |  Flags     =
// |   |  ExpTime   = Relative: 21600.0 seconds
// |   |  ConsIngress= 1
// |   |  ConsEgress= 0
// |   |  MAC       = 0xf176016b26cf

func main() {
	// Prerequisites:
	// 1. Create the files master0.key, master1.key, both containing the forwarding key
	// 2. This forwarding key can be found on a BR (/etc/scion/router/<IA>/keys/)

	// pathBytes, err := base64.StdEncoding.DecodeString("AAAhAgAABoxmOerKAADCQWY56rEBAMEAZjnpvAA/AAEAAA3eBgbH2AA/AAAAGKXvlpMaiQA/ABUA\nAAYZDl3o5gA/ABAACKXzY6WaNQA/AAgAGyZl2hkg9wA/AAAACn9O26DewgA/AAAAFWiczrxJjAA/\nAAEAAEVXW3JiTw==")
	// if err != nil {
	// 	panic(err)
	// }
	// raw := &scion.Raw{}
	// if err := raw.DecodeFromBytes(pathBytes); err != nil {
	// 	panic(err)
	// }
	// infoField, err := raw.GetCurrentInfoField()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("Info field", infoField)
	// hf, err := raw.GetCurrentHopField()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("Hop field", hf)

	// load the key
	masterKey, err := keyconf.LoadMaster(".")
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	router_secret := masterKey.Key0

	// println("Key length: ", len(router_secret))
	// println("Key:      ", hex.EncodeToString(router_secret))

	// As in router/control/conf.go line 126
	key0 := control.DeriveHFMacKey(router_secret)
	println("Key0 hex: ", hex.EncodeToString(key0))

	// compute MAC
	mac_hash_fn, err := scrypto.InitMac(key0)
	if err != nil {
		fmt.Printf("%v\n", err)
	}

	mac_hash_fn.Reset()

	// ###[ Info Field ]###
	//   Flags     =
	//   RSV       = 0
	//   SegID     = 0xfc40
	//   Timestamp = 2024-04-25 16:27:04
	t_str := "2024-04-25 14:27:04" // IMPORTANT: the time must be in UTC (so -2h)
	t, err := time.Parse("2006-01-02 15:04:05", t_str)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	info := path.InfoField{SegID: 0xfc40, ConsDir: false, Peer: false, Timestamp: util.TimeToSecs(t)}
	println(info.String())

	// ###[ Hop field ]###
	//   Flags     =
	//   ExpTime   = Relative: 21600.0 seconds
	//   ConsIngress= 1
	//   ConsEgress= 0
	//   MAC       = 0xf614cc47b032

	// 21600 = (x + 1) * (24 * 60 * 60 / 256) => x = 63
	hf0 := path.HopField{ConsIngress: 1, ConsEgress: 0, ExpTime: 63}
	// hf1 := path.HopField{ConsIngress: 0, ConsEgress: 24, ExpTime: 63}

	// updateNonConsDirIngressSegID()
	// hexString := "f614cc47b032"
	// bytes, _ := hex.DecodeString(hexString)
	// var fixedSizeByteArray [6]byte
	// copy(fixedSizeByteArray[:], bytes[:6])
	// info.UpdateSegID(fixedSizeByteArray)

	expected_mac := "f614cc47b032"
	mac_hash_fn.Reset()
	mac_value := path.FullMAC(mac_hash_fn, info, hf0, nil)
	fmt.Printf("Calc MAC: %x, expected: %s\n", mac_value[:6], expected_mac)
	// equal := mac2 == fixedSizeByteArray
	// fmt.Printf("Equal: %v\n", equal)
}
