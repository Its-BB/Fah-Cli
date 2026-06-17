package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"fahscan/pkg/types"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func Default() types.Config {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".fahscan")
	return types.Config{
		DefaultProfile:   "quick",
		MaxConcurrency:   25,
		ConnectTimeoutMS: 2000,
		BannerTimeoutMS:  1500,
		HTTPTimeoutMS:    3000,
		TLSTimeoutMS:     3000,
		MaxCustomPorts:   100,
		AllowLocalhost:   true,
		AllowPrivateIP:   true,
		OutputFormat:     "table",
		Theme:            "monochrome",
		SaveRawEvidence:  true,
		ConfigPath:       filepath.Join(base, "config.yaml"),
		DBPath:           filepath.Join(base, "fahscan.db"),
	}
}

func Load() (types.Config, error) {
	cfg := Default()
	v := viper.New()
	v.SetConfigFile(cfg.ConfigPath)
	setDefaults(v, cfg)
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) && !os.IsNotExist(err) {
			return cfg, err
		}
	} else if err := v.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	def := Default()
	cfg.ConfigPath = def.ConfigPath
	cfg.DBPath = def.DBPath
	return cfg, nil
}

func Init() (types.Config, error) {
	cfg := Default()
	if err := os.MkdirAll(filepath.Dir(cfg.ConfigPath), 0o755); err != nil {
		return cfg, err
	}
	if _, err := os.Stat(cfg.ConfigPath); err == nil {
		return Load()
	}
	return cfg, Save(cfg)
}

func Save(cfg types.Config) error {
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = Default().ConfigPath
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ConfigPath), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(cfg.ConfigPath, data, 0o600)
}

func Reset() (types.Config, error) {
	cfg := Default()
	return cfg, Save(cfg)
}

func Map(cfg types.Config) map[string]any {
	return map[string]any{
		"default_profile":    cfg.DefaultProfile,
		"max_concurrency":    cfg.MaxConcurrency,
		"connect_timeout_ms": cfg.ConnectTimeoutMS,
		"banner_timeout_ms":  cfg.BannerTimeoutMS,
		"http_timeout_ms":    cfg.HTTPTimeoutMS,
		"tls_timeout_ms":     cfg.TLSTimeoutMS,
		"max_custom_ports":   cfg.MaxCustomPorts,
		"allow_localhost":    cfg.AllowLocalhost,
		"allow_private_ip":   cfg.AllowPrivateIP,
		"output_format":      cfg.OutputFormat,
		"theme":              cfg.Theme,
		"save_raw_evidence":  cfg.SaveRawEvidence,
	}
}

func Set(cfg *types.Config, key, value string) error {
	switch key {
	case "default_profile":
		cfg.DefaultProfile = value
	case "max_concurrency":
		return setInt(value, &cfg.MaxConcurrency)
	case "connect_timeout_ms":
		return setInt(value, &cfg.ConnectTimeoutMS)
	case "banner_timeout_ms":
		return setInt(value, &cfg.BannerTimeoutMS)
	case "http_timeout_ms":
		return setInt(value, &cfg.HTTPTimeoutMS)
	case "tls_timeout_ms":
		return setInt(value, &cfg.TLSTimeoutMS)
	case "max_custom_ports":
		return setInt(value, &cfg.MaxCustomPorts)
	case "allow_localhost":
		return setBool(value, &cfg.AllowLocalhost)
	case "allow_private_ip":
		return setBool(value, &cfg.AllowPrivateIP)
	case "output_format":
		cfg.OutputFormat = value
	case "theme":
		if value != "monochrome" {
			return fmt.Errorf("theme must be monochrome")
		}
		cfg.Theme = value
	case "save_raw_evidence":
		return setBool(value, &cfg.SaveRawEvidence)
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}

func Validate(cfg types.Config) error {
	if cfg.MaxConcurrency < 1 || cfg.MaxConcurrency > 256 {
		return fmt.Errorf("max_concurrency must be between 1 and 256")
	}
	if cfg.MaxCustomPorts > 100 {
		return fmt.Errorf("max_custom_ports cannot exceed 100")
	}
	if cfg.Theme != "monochrome" {
		return fmt.Errorf("only monochrome theme is supported")
	}
	return nil
}

func setDefaults(v *viper.Viper, cfg types.Config) {
	m := Map(cfg)
	for k, val := range m {
		v.SetDefault(k, val)
	}
}

func setInt(raw string, dst *int) error {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	*dst = n
	return nil
}

func setBool(raw string, dst *bool) error {
	b, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	*dst = b
	return nil
}

func KnownKeys() []string {
	keys := make([]string, 0, len(Map(Default())))
	for k := range Map(Default()) {
		keys = append(keys, k)
	}
	return keys
}

func TypeOf(key string) string {
	if v, ok := Map(Default())[key]; ok {
		return reflect.TypeOf(v).String()
	}
	return ""
}

type FieldInfo struct {
	Key         string
	Type        string
	Default     any
	Description string
}

func Schema() []FieldInfo {
	def := Default()
	descriptions := map[string]string{
		"default_profile":    "Scan profile used when --profile and --ports are omitted.",
		"max_concurrency":    "Maximum parallel TCP connect attempts.",
		"connect_timeout_ms": "TCP connect timeout in milliseconds.",
		"banner_timeout_ms":  "Passive banner read timeout in milliseconds.",
		"http_timeout_ms":    "HTTP passive request timeout in milliseconds.",
		"tls_timeout_ms":     "TLS handshake and certificate collection timeout in milliseconds.",
		"max_custom_ports":   "Maximum custom ports accepted by --ports.",
		"allow_localhost":    "Allow localhost and loopback targets.",
		"allow_private_ip":   "Allow RFC1918 private IPv4 targets.",
		"output_format":      "Preferred terminal output format.",
		"theme":              "Terminal theme; v1 supports monochrome only.",
		"save_raw_evidence":  "Store raw passive evidence such as banners in the scan database.",
	}
	values := Map(def)
	keys := KnownKeys()
	sort.Strings(keys)
	out := make([]FieldInfo, 0, len(keys))
	for _, key := range keys {
		out = append(out, FieldInfo{Key: key, Type: TypeOf(key), Default: values[key], Description: descriptions[key]})
	}
	return out
}
