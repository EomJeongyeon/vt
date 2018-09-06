package loadconf_test

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/EomJeongyeon/vt/loadconf"
)

func TestSetConfigController(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	loadconf.SetConfigController()

	antivirusList := loadconf.ConfigVTInfo.Virustotal.AntivirusList

	//var sb strings.Builder

	queryColoumn := []string{}
	queryResult := []string{}

	//s := []string{"foo", "bar", "baz"}
	//fmt.Println(strings.Join(s, ", "))

	antivirusResult := make(map[string]interface{})
	antivirusResult["Bkav"] = "dropper"
	antivirusResult["McAfee"] = "trojan"
	antivirusResult["Zillya"] = "block"

	log.Println(antivirusResult)

	for _, v := range antivirusList {
		//log.Println(v)
		if result, exist := antivirusResult[v]; exist {
			log.Println(v)

			newVal := strings.ToLower(v)
			newVal = strings.Replace(newVal, "-", "_", -1)

			newExist := `'` + result.(string) + `'`

			queryColoumn = append(queryColoumn, newVal)
			queryResult = append(queryResult, newExist)
			//log.Println(newV)
			//newV += ", "
			//sb.WriteString(newV)
		}

	}
	queryCol := strings.Join(queryColoumn, ", ")
	queryRes := strings.Join(queryResult, ", ")

	query := fmt.Sprintf(`INSERT INTO virustotal (mal_idx, md5, sha256, positives, %s)
		VALUES (%d,'%s','%s',%d,%s) ON CONFLICT DO NOTHING RETURNING idx;`,
		queryCol, 1, "testMd5", "testSha256", 100, queryRes)

	log.Println(query)
	//log.Println(sb.String())
}
