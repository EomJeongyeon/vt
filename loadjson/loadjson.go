package loadjson

import (
	"bufio"
	"encoding/json"
	"log"
	"os"

	"github.com/EomJeongyeon/vt/common"
	"github.com/EomJeongyeon/vt/virustotal"
)

// FileScans : scans 구조체
type FileScans struct {
	Detected bool   `json:"detected"`
	Version  string `json:"verbose_msg"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

// Report : VirusTotal Report 구조체
type Report struct {
	ResponseCode int                  `json:"response_code"`
	VerboseMsg   string               `json:"verbose_msg"`
	Resource     string               `json:"resource"`
	ScanID       string               `json:"scan_id"`
	Md5          string               `json:"md5"`
	Sha1         string               `json:"sha1"`
	Sha256       string               `json:"sha256"`
	ScanDate     string               `json:"scan_date"`
	Permalink    string               `json:"permalink"`
	Positives    uint16               `json:"positives"`
	Total        uint16               `json:"total"`
	Scans        map[string]FileScans `json:"scans"`
}

// VtReport : VirusTotal Report
var VtReport = &Report{}

// LoadJSON : sdfasdf
func LoadJSON(vtJSONPath string, idx int, sha256 string) {
	//vtJSONPath := "vt.json"

	var vtBuf []byte
	file, err := os.Open(vtJSONPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		vtBuf = append(vtBuf[:], scanner.Bytes()[:]...)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalln(err)
	}

	var report = &common.RPVTFileReportBlock{}

	err = json.Unmarshal(vtBuf, &report)
	if err != nil {
		log.Println(err)
	}

	// Parsing & Store DB
	virustotal.ParseVTReport(*report, idx, sha256)

	/*
		err = json.Unmarshal(vtBuf, VtReport)
		if err != nil {
			log.Fatalln(err)
		}

		if VtReport.ResponseCode != 1 {
			log.Printf("[ViruslTotal] No Response\n")
			return
		}
	*/

	//	val, exists := VtReport.Scans["TheHacker"]
	//	if !exists {
	//		println("No TheHacker")
	//	}
	//	log.Println(val)

	//	for k := range VtReport.Scans {
	//		if k == "TheHacker" {
	//			fmt.Printf("key[%s] value[%s]\n", k, VtReport.Scans[k].Result)
	//		}
	//	}

	//	_, exists := VtReport.Scans["merong"]
	//	if !exists {
	//		println("No TheHacker")
	//	}
	//	log.Println(val)

	//log.Printf("%#v\n", VtReport)
}
