package virustotal_test

import (
	"io/ioutil"
	"log"
	"testing"
	"time"

	"github.com/EomJeongyeon/vt/loadconf"
	"github.com/EomJeongyeon/vt/virustotal"
)

func TestReadPackedFile(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	storagePath := "/data/test_integrated_storage/node1/00c9567ba7c71f8bc941a44e374cbf0a499dc93fa69e66a6f6918c3b00cedc91/1"
	data := virustotal.ReadPackedFile(storagePath)
	ioutil.WriteFile(storagePath+"/binary_test", data, 0644)
}

func TestGetScanReport(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	loadconf.SetConfigController()

	apiKeyList := []string{"11111111111111111111111111111111111111111111111111111111", "a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088"}

	for idx, apiKey := range apiKeyList {
		if idx == 0 {
			virustotal.GetScanReport(apiKey, 1)
		} else {
			virustotal.GetScanReport(apiKey, 16)
		}
	}

}

func TestTimeStringToTimestamp(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var tempTime time.Time

	if ret, status := virustotal.TimeStringToTimestamp("2018-08-31 17:13:33"); status {
		tempTime = ret
	}
	//log.Println(time.Time{})
	//zeroTime := time.Time{}

	log.Println(tempTime.IsZero()) // zero일 때, true 반환.

	/*
		if zeroTime == tempTime {
			log.Println("test OK")
		} else {
			log.Println("test NO :(")
		}
	*/
}

func TestVTScanMain(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	apiKey := ""
	malIdx := 1
	sha256 := ""
	virustotal.VTScanMain(apiKey, malIdx, sha256)
}
