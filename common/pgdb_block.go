package common

import "time"

// NoVTSample : no VT Sample
type NoVTSample struct {
	Idx    int
	Sha256 string
}

// PGVirustotalBlock : Postgres Virustotal Block
type PGVirustotalBlock struct {
	MalIdx        int
	Md5           string
	Sha256        string
	ScanDate      time.Time
	Positives     int
	AntivirusList map[string]interface{}
}
