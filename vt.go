package main

import (
	"log"
	"time"

	"github.com/EomJeongyeon/vt/loadconf"
	"github.com/EomJeongyeon/vt/virustotal"
)

type vtAPIBlock struct {
	apiKey    string
	sleepTime int
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	loadconf.SetConfigController()

	var vtAPI map[string]vtAPIBlock
	vtAPI = make(map[string]vtAPIBlock)

	if loadconf.ConfigVTInfo.Virustotal.VTPrivate.IsPrivate == true {
		if (loadconf.ConfigVTInfo.Virustotal.VTPrivate.APIKey != "") && (loadconf.ConfigVTInfo.Virustotal.VTPrivate.DailyLimit > 0) {
			vtAPI["private"] = vtAPIBlock{loadconf.ConfigVTInfo.Virustotal.VTPrivate.APIKey, 1}
		}
	}

	if loadconf.ConfigVTInfo.Virustotal.VTPublic.IsPublic == true {
		if loadconf.ConfigVTInfo.Virustotal.VTPublic.APIKey != "" {
			vtAPI["public"] = vtAPIBlock{loadconf.ConfigVTInfo.Virustotal.VTPublic.APIKey, 16}
		}
	}

	if len(vtAPI) == 0 {
		log.Fatalln("Please Check vt_config.json")
	}

	scan := loadconf.ConfigVTInfo.Virustotal.Scan

	keyTypeList := [...]string{"private", "public"}

	for {

		for _, k := range keyTypeList {
			if _, ok := vtAPI[k]; ok {
				log.Println(k)
				log.Println("key:", vtAPI[k].apiKey)

				if status := virustotal.VTMain(vtAPI[k].apiKey, vtAPI[k].sleepTime, scan); !status {
					log.Fatalln("Error ! - Check status ")
				}

				// Get Scan Report
				virustotal.GetScanReport(vtAPI[k].apiKey, vtAPI[k].sleepTime)

				time.Sleep(10 * time.Second)
			}
		}

	}
}
