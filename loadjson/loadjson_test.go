package loadjson_test

import (
	"log"
	"testing"

	"github.com/EomJeongyeon/vt/loadconf"
	"github.com/EomJeongyeon/vt/loadjson"
)

func TestLoadJSON(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	loadconf.SetConfigController()

	vtJSONPath := "/data/gowork/src/github.com/EomJeongyeon/vt/loadjson/vt.json"
	idx := 1
	sha256 := "20995e05fd99a96feb282b67c3004eea6ae9405df559f8a86e1d7fa83e985f7c"

	loadjson.LoadJSON(vtJSONPath, idx, sha256)
}
