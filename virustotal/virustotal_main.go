package virustotal

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/EomJeongyeon/vt/database/pg"
)

// VTMain : Virustotal Main function
func VTMain(apiKey string, sleepTime int, scan bool) bool {
	log.Println("VTMain Start")

	var latestIdx int
	var latestSha256 string

	vtPath := "config/vt.txt"

	latestIdx, latestSha256 = readFile(vtPath)

	log.Println("latest Idx: ", latestIdx)
	log.Println("latest sha256: ", latestSha256)

	// Initial
	if latestIdx == 0 {
		latestIdx = 1
	}

	var recovIdx int
	var recovSha256 string

	defer func() {
		if r := recover(); r != nil {
			writeFile(vtPath, recovIdx, recovSha256)
			log.Fatalln("[ERR]API Run Error !!!")
			return
		}
	}()

	var reportError bool
	var status int

	_idx := 1
	limitCnt := 51
	if latestSha256 == "" {
		_idx = 0
		limitCnt = 50
	}

	rows, err := pg.GetNoVTSamples(latestIdx, limitCnt)
	if rows == nil || err != nil {
		log.Fatalln("[ERR] Please Check DB")
		return false
	}
	rowCnt := len(rows)

	log.Println("row count: ", rowCnt-_idx)
	if (rowCnt - _idx) <= 0 {
		//rowCnt = 0 or 1
		log.Println("No Samples")
		return true
	}

	log.Println("idx", rows[0].Idx)
	log.Println("sha256", rows[0].Sha256)

	if latestSha256 != "" && (rows[0].Idx != latestIdx || rows[0].Sha256 != latestSha256) {
		log.Fatalln("[ERR] Please Check malwares Table <-> config/vt.txt")
		return false
	}

	// recovery ---> 아래 for문에서 에러 발생 시 row.Idx, row.Sha256 저장.
	for _, row := range rows[_idx:] {

		log.Println(row.Idx)
		log.Println(row.Sha256)

		report, status, err := GetFileReport(apiKey, row.Sha256, row.Idx)
		if report == nil || status != 200 {
			// status : -1 || 204 || 400 || 403

			log.Println("No Report (idx, sha256)", row.Idx, row.Sha256)
			log.Println(err)

			reportError = true
			break
		}

		// No report --> scan option check
		if report.VTResponse.ResponseCode != 1 {
			log.Println("ResponseCode != 1, mal_idx: ", row.Idx)
			log.Println("ResponseCode !=1 : ", report.VTResponse.ResponseCode)
			// if scan == true --> PostFileScan
			// status_code = 0 : not present in VirusTotal's dataset
			//              -2 : is still queued for analysis
			//               1 : present
			if report.VTResponse.ResponseCode == 0 && scan == true {
				log.Println("Scan File Start - status 0")
				VTScanMain(apiKey, row.Idx, row.Sha256)
				log.Println("Scan File End - status 0")
			}

			if report.VTResponse.ResponseCode == -2 {
				log.Println("Scan File Store Start - status -2")
				StoreFileScan(row.Idx, row.Sha256)
				log.Println("Scan File Store End - status -2")
			}
			continue
		}

		if report.Sha256 != row.Sha256 {
			log.Println("[ERR]VirusTotal Sha256 != DB Sha256, DB Sha256: ", row.Sha256)
			continue
		}

		// Parsing & Store DB
		ParseVTReport(*report, row.Idx, row.Sha256)

		recovIdx = row.Idx
		recovSha256 = row.Sha256

		time.Sleep(time.Duration(sleepTime) * time.Second)
	}

	if reportError == true {
		// report error return Main
		// return false
		log.Println("reportError == true")
		if recovIdx != 0 && recovSha256 != "" {
			log.Println("Store Idx: ", recovIdx)
			log.Println("Store Sha256: ", recovSha256)
			writeFile(vtPath, recovIdx, recovSha256)
			log.Println("Store before idx, sha256 Complete")
		}

		if status == -1 {
			log.Println("Status -1, Return False")
			return false
		}

		return true
	}

	latestIdx = rows[rowCnt-1].Idx
	latestSha256 = rows[rowCnt-1].Sha256

	writeFile(vtPath, latestIdx, latestSha256)

	log.Println("VTMain End")
	return true
}

func readFile(fileName string) (latestIdx int, latestSha256 string) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[openFile] File OPEN Error", r)
		}
	}()

	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	var data string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		data = scanner.Text() // data: type string --> reflect.TypeOf(data)
		break
	}

	log.Println("[openFile] latest data(idx,sha256): ", data)

	fmt.Sscanf(data, "%d,%s", &latestIdx, &latestSha256)

	return latestIdx, latestSha256
}

func writeFile(fileName string, latestIdx int, latestSha256 string) error {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[writeFile] File Write Error", r)
		}
	}()

	output := fmt.Sprintf("%d,%s", latestIdx, latestSha256)
	outputByte := []byte(output)

	err := ioutil.WriteFile(fileName, outputByte, 0644)
	return err
}

// GetScanReport : Get scan report
func GetScanReport(apiKey string, sleepTime int) {
	log.Println("GetScanReport Start")

	fileName := "config/scan.txt"

	file, err := os.Open(fileName)
	if err != nil {
		log.Println(err)
		log.Println("No Scan file")
		return
	}
	defer file.Close()

	var scanList map[string]bool

	scanList = make(map[string]bool)

	scanFile := bufio.NewScanner(file)
	for scanFile.Scan() {
		scanList[scanFile.Text()] = false
	}

	var idx int
	var sha256 string

	for line, check := range scanList {
		log.Println(line, check)

		fmt.Sscanf(line, "%d,%s", &idx, &sha256)

		log.Println(idx, sha256)

		report, status, err := GetFileReport(apiKey, sha256, idx)
		if report == nil || status != 200 {
			log.Println("GetFileReport Error")
			log.Println(err)
			break
		}

		if report.Sha256 != sha256 {
			log.Println("[ERR]VirusTotal Sha256 != DB Sha256, DB Sha256: ", sha256)
			continue
		}

		if report.VTResponse.ResponseCode == 1 {
			// Parsing & Store DB
			status := ParseVTReport(*report, idx, sha256)
			if status == true {
				scanList[line] = true
			}
		}

		time.Sleep(time.Duration(sleepTime) * time.Second)

	}

	// Store file

	//var buffer bytes.Buffer
	var scan []byte
	for line, check := range scanList {
		if check == false {
			//buffer.WriteString(line + "\n")
			log.Println(line)
			line = line + "\n"
			scan = append(scan, line...)
		}

	}
	//log.Println(scan)
	err = ioutil.WriteFile(fileName, scan, 0644)
	if err != nil {
		log.Println(err)
	}
	log.Println("GetScanReport End")
}
