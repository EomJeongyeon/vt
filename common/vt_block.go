package common

// VTResponse : Virustotal Response code N message
type VTResponse struct {
	ResponseCode int    `json:"response_code"`
	Message      string `json:"verbose_msg"`
}

// FileScans : Virustotal Vaccine Report
type FileScans struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

// RPVTFileReportBlock : Virustotal Response File Report Block before: RPVTFileReportBlock, RPVirustotalBlock
type RPVTFileReportBlock struct {
	VTResponse
	Resource  string               `json:"resource"`
	ScanID    string               `json:"scan_id"`
	Md5       string               `json:"md5"`
	Sha1      string               `json:"sha1"`
	Sha256    string               `json:"sha256"`
	ScanDate  string               `json:"scan_date"`
	Permalink string               `json:"permalink"`
	Positives int                  `json:"positives"`
	Total     int                  `json:"total"`
	Scans     map[string]FileScans `json:"scans"`
}

// RPVTFileScanBlock : Virustotal Response File Scan Block
type RPVTFileScanBlock struct {
	VTResponse
	Permalink string `json:"permalink"`
	Resource  string `json:"resource"`
	ScanID    string `json:"scan_id"`
	Sha256    string `json:"sha256"`
}

// RPVTScanBlock : Virustotal Scan Block
type RPVTScanBlock struct {
	VTResponse
	ScanID    string `json:"scan_id"`
	Resource  string `json:"resource"`
	Permalink string `json:"permalink"`
	Md5       string `json:"md5"`
	Sha1      string `json:"sha1"`
	Sha256    string `json:"sha256"`
}
