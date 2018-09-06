package virustotal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/EomJeongyeon/vt/common"
	"github.com/EomJeongyeon/vt/database/pg"
	"github.com/EomJeongyeon/vt/loadconf"
)

// StoreFileReport : Store Report Json
func StoreFileReport(contents []byte, malIdx int) {
	// contents --> json
	if storagePath := pg.GetStoragePath(malIdx); storagePath != "" {
		err := ioutil.WriteFile(storagePath+"/vt.json", contents, 0644)
		if err != nil {
			log.Println("[ERR]Write vt.json, ", err)
		}
	}
}

// GetFileReport : GET VirusTotal File Report
func GetFileReport(apikey string, sha256 string, malIdx int) (*common.RPVTFileReportBlock, int, error) {
	//var statusCode int

	u, err := url.Parse("https://www.virustotal.com/vtapi/v2/file/report")

	params := url.Values{"apikey": {apikey}, "resource": {sha256}}

	resp, err := http.PostForm(u.String(), params)
	if err != nil {
		log.Println(err)
		return nil, -1, err
	}
	defer resp.Body.Close()

	// 204 : request rate limit exceeded
	// 400 : Bad request
	// 403 : Forbidden

	if resp.StatusCode != 200 {
		log.Println("[virusotal] Status: ", resp.Status)
		return nil, resp.StatusCode, nil
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return nil, -1, err
	}

	// virustotal Report --> Store json file
	StoreFileReport(contents, malIdx)

	var report = &common.RPVTFileReportBlock{}

	err = json.Unmarshal(contents, &report)
	if err != nil {
		log.Println(err)
		return nil, -1, err
	}

	return report, 200, err
}

// ReadPackedFile : Read .tgz file
func ReadPackedFile(storagePath string) []byte {
	// 참고: https://gist.github.com/indraniel/1a91458984179ab4cf80

	var data []byte

	f, err := os.Open(storagePath + "/report.tgz")
	if err != nil {
		log.Println("No Open file: ", storagePath+"/report.tgz")
	}
	defer f.Close()

	archive, err := gzip.NewReader(f)
	if err != nil {
		log.Println("There is a problem with os.Open ", storagePath+"/report.tgz")
	}

	// gzip ---> 압축 푸는 로직
	var gunzipBuf bytes.Buffer
	_, err = gunzipBuf.ReadFrom(archive)
	if err != nil {
		log.Println(err)
	}

	tarByte := bytes.NewReader(gunzipBuf.Bytes())

	tr := tar.NewReader(tarByte)
	archive.Close()
	// 여기까지

	//tr := tar.NewReader(archive)

	for {
		hdr, err := tr.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Println(err)
		}

		log.Println("name: ", hdr.Name)

		if hdr.Name == "binary" {
			//log.Println("binary !!!")
			//log.Println("hdr.Typeflag", hdr.Typeflag)
			//log.Println("tar.TypeReg", tar.TypeReg)
			//log.Println("hdr.Size", hdr.Size)
			// virustotal File size limit is 32MB
			if hdr.Size <= (32 * 1024 * 1024) {
				log.Println("size <= 32 MB")
				data = make([]byte, hdr.Size)
				log.Println(len(data))
				n, err := tr.Read(data)
				if err != nil && err != io.EOF {
					log.Println(err)
				}
				if int64(n) != hdr.Size {
					log.Println("[ERR]Fail Read File! size: ", n)
				}
				// test
				// ioutil.WriteFile(storagePath+"/binary", data, 0755)
			} else {
				log.Println("Fail Scan, size > 32MB")
			}
			break
		}
	}
	return data
}

// PostFileScan : Virustotal File Scan
func PostFileScan(apiKey string, data []byte, fileName string) (*common.RPVTScanBlock, error) {

	bodyBuf := &bytes.Buffer{}
	wBodyBuf := multipart.NewWriter(bodyBuf)

	wBodyBuf.WriteField("apikey", apiKey)

	fWriter, err := wBodyBuf.CreateFormFile("file", fileName) //fWriter: io.Writer
	if err != nil {
		return nil, err
	}

	_, err = fWriter.Write(data)
	if err != nil {
		return nil, err
	}

	contentType := wBodyBuf.FormDataContentType()
	err = wBodyBuf.Close()
	if err != nil {
		return nil, err
	}

	uri := "https://www.virustotal.com/vtapi/v2/file/scan"
	req, err := http.NewRequest("POST", uri, bodyBuf)
	if err != nil {
		log.Println(err)
	}

	req.Header.Set("Content-Type", contentType)
	client := &http.Client{
		Timeout: time.Duration(300 * time.Second),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var scanResponse = &common.RPVTScanBlock{}
	err = json.Unmarshal(contents, &scanResponse)

	return scanResponse, err

}

// VTScanMain : file Scan Main function
func VTScanMain(apiKey string, malIdx int, sha256 string) {
	storagePath := pg.GetStoragePath(malIdx)
	data := ReadPackedFile(storagePath)
	if int64(len(data)) == 0 {
		return
	}

	scanResponse, _ := PostFileScan(apiKey, data, sha256)

	if scanResponse.ResponseCode == 1 {
		// Store idx, sha256, Permalink
		err := StoreFileScan(malIdx, sha256)
		if err != nil {
			return
		}
	} else {
		log.Println("[ERR]Scan file error!, response_code: ", scanResponse.ResponseCode)
	}
}

// StoreFileScan : Store file Scan permalink
func StoreFileScan(malIdx int, sha256 string) error {
	filename := "config/scan.txt"

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Open file error, config/scan.txt ", err)
		return err
	}
	defer f.Close()

	text := fmt.Sprintf("%d,%s\n", malIdx, sha256)
	log.Println(text)

	if _, err = f.WriteString(text); err != nil {
		log.Println("Write file error, config/scan.txt ", err)
		return err
	}
	return nil
}

// ParseVTReport : Parse VirusTotal Report & Store Postgresql
func ParseVTReport(report common.RPVTFileReportBlock, malIdx int, sha256 string) bool {

	log.Println(report)

	tmpVirustotalInfo := common.PGVirustotalBlock{
		MalIdx:    malIdx,
		Md5:       report.Md5,
		Sha256:    sha256,
		Positives: report.Positives,
	}

	if t, status := TimeStringToTimestamp(report.ScanDate); status {
		//log.Println("time OK")
		tmpVirustotalInfo.ScanDate = t
	}

	antivirusList := loadconf.ConfigVTInfo.Virustotal.AntivirusList
	//log.Println(antivirusList)

	//tmpVirustotalInfo.AntivirusList = map[string]interface{}{}
	tmpVirustotalInfo.AntivirusList = make(map[string]interface{}) // <- 정석, 반드시 빈 맵으로 초기화 필요

	for _, k := range antivirusList {
		if _, exists := report.Scans[k]; exists {
			//log.Println(report.Scans[k].Result)
			tmpVirustotalInfo.AntivirusList[k] = report.Scans[k].Result
		}

	}

	//	for k := range loadjson.VtReport.Scans {
	//		if k == "TheHacker" {
	//			fmt.Printf("key[%s] value[%s]\n", k, loadjson.VtReport.Scans[k].Result)
	//		}
	//	}

	//for k := range report.Scans {
	//	if k == "Bkav" {
	//		tmpVirustotalInfo.Bkav = report.Scans[k].Result
	//	}
	//}

	status := pg.InsertVirustotalTbl(tmpVirustotalInfo)

	return status
}

// TimeStringToTimestamp : Time String to Timestamp
func TimeStringToTimestamp(timeStr string) (time.Time, bool) {
	layout := "2006-01-02 15:04:05" // 정해진 layout --> 변경하면 안 된다.
	t, err := time.Parse(layout, timeStr)
	if err != nil {
		log.Println(err)
		return t, false
	}
	return t, true
}
