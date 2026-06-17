package types

import "time"

type Config struct {
	DefaultProfile   string `mapstructure:"default_profile" yaml:"default_profile" json:"default_profile"`
	MaxConcurrency   int    `mapstructure:"max_concurrency" yaml:"max_concurrency" json:"max_concurrency"`
	ConnectTimeoutMS int    `mapstructure:"connect_timeout_ms" yaml:"connect_timeout_ms" json:"connect_timeout_ms"`
	BannerTimeoutMS  int    `mapstructure:"banner_timeout_ms" yaml:"banner_timeout_ms" json:"banner_timeout_ms"`
	HTTPTimeoutMS    int    `mapstructure:"http_timeout_ms" yaml:"http_timeout_ms" json:"http_timeout_ms"`
	TLSTimeoutMS     int    `mapstructure:"tls_timeout_ms" yaml:"tls_timeout_ms" json:"tls_timeout_ms"`
	MaxCustomPorts   int    `mapstructure:"max_custom_ports" yaml:"max_custom_ports" json:"max_custom_ports"`
	AllowLocalhost   bool   `mapstructure:"allow_localhost" yaml:"allow_localhost" json:"allow_localhost"`
	AllowPrivateIP   bool   `mapstructure:"allow_private_ip" yaml:"allow_private_ip" json:"allow_private_ip"`
	OutputFormat     string `mapstructure:"output_format" yaml:"output_format" json:"output_format"`
	Theme            string `mapstructure:"theme" yaml:"theme" json:"theme"`
	SaveRawEvidence  bool   `mapstructure:"save_raw_evidence" yaml:"save_raw_evidence" json:"save_raw_evidence"`
	ConfigPath       string `yaml:"-" json:"-"`
	DBPath           string `yaml:"-" json:"-"`
}

type Target struct {
	ID        int64     `json:"id"`
	Value     string    `json:"value"`
	Type      string    `json:"type"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

type Scan struct {
	ID         int64     `json:"id"`
	Target     string    `json:"target"`
	Profile    string    `json:"profile"`
	Ports      []int     `json:"ports"`
	Status     string    `json:"status"`
	RiskScore  int       `json:"risk_score"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
}

type Service struct {
	ID        int64             `json:"id"`
	ScanID    int64             `json:"scan_id"`
	Port      int               `json:"port"`
	Protocol  string            `json:"protocol"`
	Service   string            `json:"service"`
	Product   string            `json:"product,omitempty"`
	Version   string            `json:"version,omitempty"`
	Banner    string            `json:"banner,omitempty"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
}

type Finding struct {
	ID             int64     `json:"id"`
	ScanID         int64     `json:"scan_id"`
	ServiceID      int64     `json:"service_id,omitempty"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	CVSS           float64   `json:"cvss,omitempty"`
	CVEID          string    `json:"cve_id,omitempty"`
	Description    string    `json:"description"`
	Evidence       string    `json:"evidence"`
	Recommendation string    `json:"recommendation"`
	Confidence     string    `json:"confidence"`
	CreatedAt      time.Time `json:"created_at"`
}

type CVERecord struct {
	ID              int64    `json:"id,omitempty"`
	CVEID           string   `json:"cve_id"`
	Vendor          string   `json:"vendor"`
	Product         string   `json:"product"`
	AffectedVersion string   `json:"affected_version"`
	Severity        string   `json:"severity"`
	CVSS            float64  `json:"cvss"`
	Description     string   `json:"description"`
	Recommendation  string   `json:"recommendation"`
	References      []string `json:"references"`
}

type AuditLog struct {
	ID        int64     `json:"id"`
	Action    string    `json:"action"`
	Metadata  string    `json:"metadata_json"`
	CreatedAt time.Time `json:"created_at"`
}

type ReportData struct {
	Scan                Scan                `json:"scan"`
	Services            []Service           `json:"services"`
	Findings            []Finding           `json:"findings"`
	Policy              []PolicyDecision    `json:"policy"`
	Remediation         []RemediationAction `json:"remediation"`
	SeveritySummary     SeveritySummary     `json:"severity_summary"`
	EvidenceFingerprint string              `json:"evidence_fingerprint"`
	AuthorizationNotice string              `json:"authorization_notice"`
	GeneratedAt         time.Time           `json:"generated_at"`
}

type PolicyDecision struct {
	ControlID string `json:"control_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Result    string `json:"result"`
	Reason    string `json:"reason"`
}

type RemediationAction struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Priority    int      `json:"priority"`
	Severity    string   `json:"severity"`
	Effort      string   `json:"effort"`
	Targets     []string `json:"targets"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
}

type SeveritySummary struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
	Total    int `json:"total"`
}
