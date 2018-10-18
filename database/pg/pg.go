package pg

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/lib/pq" //psql

	"github.com/EomJeongyeon/vt/common"
	"github.com/EomJeongyeon/vt/loadconf"
)

// DBConn : DB Connection Return
func DBConn() *sql.DB {
	var smode string
	var err error
	var db *sql.DB

	if !loadconf.ConfigPGInfo.IntegratedPGDB.SSLMode {
		smode = "disable"
	}

	addrArr := strings.Split(loadconf.ConfigPGInfo.IntegratedPGDB.Addr, ":")
	if len(addrArr) < 2 {
		log.Fatalln("PGDB split error")
	}

	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		addrArr[0], addrArr[1], loadconf.ConfigPGInfo.IntegratedPGDB.ID,
		loadconf.ConfigPGInfo.IntegratedPGDB.Password, loadconf.ConfigPGInfo.IntegratedPGDB.DBName, smode)

	db, err = sql.Open("postgres", dbinfo)
	if err != nil {

		log.Println(err)
		return nil
	}
	return db
}

// GetNoVTSamples : No VirusTotal Sample list
func GetNoVTSamples(latestIdx int, limit int) ([]*common.NoVTSample, error) {
	// rows == *sql.Rows

	db := DBConn()
	if db == nil {
		log.Println("[ERR]Do not connect DB")
		return nil, nil
	}
	defer db.Close()

	//rows, err := db.Query(`SELECT idx, sha256 FROM malwares WHERE sha256!='' AND sha256 IS NOT NULL and vt_check=null ORDER BY idx`)
	rows, err := db.Query(`SELECT idx, sha256 FROM malwares 
						WHERE idx>=$1 AND sha256!='' AND sha256 IS NOT NULL ORDER BY idx limit $2`, latestIdx, limit)
	if err != nil {
		// err != sql.ErrNoRows
		log.Println(err)
		return nil, err
	}
	defer rows.Close()

	// Create empty slice of struct pointers
	noVTSampleList := []*common.NoVTSample{}

	for rows.Next() {
		// Create struct and append it to the slice
		noVT := new(common.NoVTSample)

		err = rows.Scan(&noVT.Idx, &noVT.Sha256)
		if err != nil {
			return noVTSampleList, err
		}
		log.Println(noVT)
		noVTSampleList = append(noVTSampleList, noVT)
	}
	return noVTSampleList, nil
}

// GetStoragePath : Get storage_path
func GetStoragePath(idx int) (storagePath string) {
	db := DBConn()
	if db == nil {
		log.Println("[ERR]Do not connect DB")
	}
	defer db.Close()

	err := db.QueryRow("SELECT storage_path FROM malwares WHERE idx=$1", idx).Scan(&storagePath)
	if err != nil {
		log.Println(err)
		return storagePath
	}

	return storagePath
}

// InsertVirustotalTbl : Insert Virustotal Report
func InsertVirustotalTbl(qr common.PGVirustotalBlock) bool {

	db := DBConn()
	if db == nil {
		log.Println("[ERR]Do not connect DB")
		return false
	}
	defer db.Close()

	configAntivirusList := loadconf.ConfigVTInfo.Virustotal.AntivirusList
	antivirusCount := len(configAntivirusList)

	queryColumn := []string{}
	queryResult := []string{}

	if !qr.ScanDate.IsZero() {
		queryColumn = []string{"scan_date"}
		tempScanDate := `'` + qr.ScanDate.Format(time.RFC3339) + `'`
		queryResult = []string{tempScanDate}
	}

	var postivies int
	tempAntivirus := []string{}

	for _, antivirus := range configAntivirusList {
		if result, exist := qr.AntivirusList[antivirus]; exist {
			newAntivirus := `"` + antivirus + `"` // "uppercase"

			newResult := `'` + result.(string) + `'`

			if newResult != `''` && newResult != `'null'` {
				postivies = postivies + 1
				tempAntivirus = append(tempAntivirus, result.(string))
			}

			queryColumn = append(queryColumn, newAntivirus)
			queryResult = append(queryResult, newResult)
		}
	}

	queryCol := strings.Join(queryColumn, ", ")
	queryRes := strings.Join(queryResult, ", ")
	queryAntivirus := strings.Join(tempAntivirus, ",")

	query := fmt.Sprintf(`INSERT INTO virustotal (mal_idx, md5, sha256, positives, %s, antivirus)
		VALUES (%d,'%s','%s',%d,%s,'%s') ON CONFLICT DO NOTHING RETURNING idx;`,
		queryCol, qr.MalIdx, qr.Md5, qr.Sha256, postivies, queryRes, queryAntivirus)

	/*
		query := fmt.Sprintf(`INSERT INTO virustotal (mal_idx, md5, sha256, scan_date, positives,
			bkav, microworld_escan, nprotect, cmc, cat_quickheal, mcafee, malwarebytes, zillya,
			aegislab, k7antivirus, k7gw, thehacker, baidu, f_prot, symantec, eset_nod32, trendmicro_housecall,
			avast, clamav, kaspersky, bitdefender, nano_antivirus, virobot, rising, ad_aware, sophos, comodo,
			f_secure, drweb, vipre, mcafee_gw_edition, emsisoft, cyren, jiangmin, webroot, avira, antiy_avl,
			kingsoft, microsoft, arcabit, superantispyware, zonealarm, gdata, ahnlab_v3, alyac, avware,
			vba32, zoner, tencent, yandex, ikarus, fortinet, avg, panda, qihoo_360)
			VALUES (%d,'%s','%s','%s',%d,
			'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',
			'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',
			'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s') ON CONFLICT DO NOTHING RETURNING idx;`,
			qr.MalIdx, qr.Md5, qr.Sha256, qr.ScanDate.Format(time.RFC3339), qr.Positives,
			qr.Bkav, qr.MicroworldEscan, qr.Nprotect, qr.Cmc, qr.CatQuickheal, qr.Mcafee, qr.Malwarebytes, qr.Zillya,
			qr.Aegislab, qr.K7antivirus, qr.K7gw, qr.Thehacker, qr.Baidu, qr.FProt, qr.Symantec, qr.EsetNod32, qr.TrendmicroHousecall,
			qr.Avast, qr.Clamav, qr.Kaspersky, qr.Bitdefender, qr.NanoAntivirus, qr.Virobot, qr.Rising, qr.AdAware, qr.Sophos, qr.Comodo,
			qr.FSecure, qr.Drweb, qr.Vipre, qr.McafeeGwEdition, qr.Emsisoft, qr.Cyren, qr.Jiangmin, qr.Webroot, qr.Avira, qr.AntiyAvl,
			qr.Kingsoft, qr.Microsoft, qr.Arcabit, qr.Superantispyware, qr.Zonealarm, qr.Gdata, qr.AhnlabV3, qr.Alyac, qr.Avware,
			qr.Vba32, qr.Zoner, qr.Tencent, qr.Yandex, qr.Ikarus, qr.Fortinet, qr.Avg, qr.Panda, qr.Qihoo360)
	*/
	//log.Println(query)

	var lastCallid int
	err := db.QueryRow(query).Scan(&lastCallid)
	if err != nil {
		log.Println(err)
		return false
	}

	vt := fmt.Sprintf("%d/%d", postivies, antivirusCount)
	// Update malwares
	query = `UPDATE malwares SET vt=$1 WHERE idx=$2 and sha256=$3`
	log.Println(query)
	res, err := db.Exec(query, vt, qr.MalIdx, qr.Sha256)
	if err != nil {
		log.Println(err)
		return false
	}
	count, err := res.RowsAffected()
	log.Println(count)

	return true
}

/*
// UpdateVTCheckCol : Update vt_check column True or False in Malwares Table
func UpdateVTCheckCol(MalIdx int, VTCheck bool) {
	db := DBConn()
	if db == nil {
		log.Println("[ERR]Do not connect DB")
		return
	}
	defer db.Close()

	stmt, err := db.Prepare("UPDATE malwares SET vt_check=$1 WHERE idx=$2")
	if err != nil {
		log.Println(err)
		return
	}

	res, err := stmt.Exec(VTCheck, MalIdx)
	if err != nil {
		log.Println(err)
		return
	}

	affect, err := res.RowsAffected()
	if err != nil {
		log.Println(err)
		return
	}

	log.Println(affect, "rows changed")
}
*/
