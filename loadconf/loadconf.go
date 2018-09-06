package loadconf

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"regexp"
)

// ConfigPG : PostgreSQL DB 구조체
type ConfigPG struct {
	IntegratedPGDB DBlock `json:"integrated_db" bson:"integrated_db"`
}

// DBlock : ConfigPG > DB
type DBlock struct {
	Addr     string `json:"addr" bson:"addr"`
	ID       string `json:"id" bson:"id"`
	DBName   string `json:"db_name,omitempty" bson:"db_name,omitempty"`
	Password string `json:"password" bson:"password"`
	SSLMode  bool   `json:"ssl_mode" bson:"ssl_mode"`
}

// ConfigVT : VirusTotal Config
type ConfigVT struct {
	Virustotal VTDBlock `json:"virustotal" bson:"virustotal"`
}

// VTDBlock : ConfigVT > VT Info
type VTDBlock struct {
	VTPrivate     VTPrivateDBlock `json:"private" bson:"private"`
	VTPublic      VTPublicDBlock  `json:"public" bson:"public"`
	Scan          bool            `json:"scan" bson:"scan"`
	AntivirusList []string        `json:"antivirus_list" bson:"antivirus_list"`
}

// VTPublicDBlock : VT Public API Info
type VTPublicDBlock struct {
	IsPublic bool   `json:"is_public" bson:"is_public"`
	APIKey   string `json:"apikey" bson:"apikey"`
}

// VTPrivateDBlock : VT Private API Info
type VTPrivateDBlock struct {
	IsPrivate  bool   `json:"is_private" bson:"is_private"`
	APIKey     string `json:"apikey" bson:"apikey"`
	DailyLimit int    `json:"daily_limit" bson:"daily_limit"`
}

// ConfigPGInfo : PostreSQL Connection String
var ConfigPGInfo = &ConfigPG{}

// ConfigVTInfo : Virustotal API Key Info
var ConfigVTInfo = &ConfigVT{}

// ReadConfFile : Read Config File
func ReadConfFile(confPath string) (confBuf []byte) {

	file, err := os.Open(confPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if matched, _ := regexp.Match("/\\*.*\\*/", scanner.Bytes()); !matched {
			confBuf = append(confBuf[:], scanner.Bytes()[:]...)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalln(err)
	}

	return confBuf
}

// SetConfigController : Config 불러오기
func SetConfigController() {

	pgConfPath := "config/config.json"
	vtConfPath := "config/vt_config.json"

	//pgConfPath := "/data/gowork/src/github.com/EomJeongyeon/vt/config/config.json"
	//vtConfPath := "/data/gowork/src/github.com/EomJeongyeon/vt/config/vt_config.json"

	// pgConfBuf : Postgres Config Buf
	pgConfBuf := ReadConfFile(pgConfPath)
	err := json.Unmarshal(pgConfBuf, ConfigPGInfo)
	if err != nil {
		log.Fatalln(err)
	}

	vtConfBuf := ReadConfFile(vtConfPath)
	err = json.Unmarshal(vtConfBuf, ConfigVTInfo)
	if err != nil {
		log.Fatalln(err)
	}

}
