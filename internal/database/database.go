package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fahscan/pkg/types"
	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
	Path string
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db := &DB{DB: raw, Path: path}
	if err := db.Migrate(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Migrate() error {
	stmts := []string{
		`create table if not exists targets (id integer primary key autoincrement, value text not null unique, type text not null, tags text not null default '[]', created_at text not null)`,
		`create table if not exists scans (id integer primary key autoincrement, target text not null, profile text not null, ports text not null, status text not null, risk_score integer not null, started_at text not null, finished_at text not null, duration_ms integer not null, error text not null default '')`,
		`create table if not exists services (id integer primary key autoincrement, scan_id integer not null, port integer not null, protocol text not null, service text not null, product text not null default '', version text not null default '', banner text not null default '', metadata_json text not null default '{}', created_at text not null)`,
		`create table if not exists findings (id integer primary key autoincrement, scan_id integer not null, service_id integer not null default 0, title text not null, severity text not null, cvss real not null default 0, cve_id text not null default '', description text not null default '', evidence text not null default '', recommendation text not null default '', confidence text not null default '', created_at text not null)`,
		`create table if not exists cves (id integer primary key autoincrement, cve_id text not null unique, vendor text not null default '', product text not null default '', affected_version text not null default '', severity text not null default '', cvss real not null default 0, description text not null default '', recommendation text not null default '', references_json text not null default '[]')`,
		`create table if not exists audit_logs (id integer primary key autoincrement, action text not null, metadata_json text not null default '{}', created_at text not null)`,
		`create table if not exists reports (id integer primary key autoincrement, scan_id integer not null, format text not null, path text not null, created_at text not null)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) AddTarget(value, typ string) (int64, error) {
	res, err := db.Exec(`insert into targets(value,type,tags,created_at) values(?,?,?,?)`, value, typ, "[]", now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) ListTargets() ([]types.Target, error) {
	rows, err := db.Query(`select id,value,type,tags,created_at from targets order by id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Target
	for rows.Next() {
		var t types.Target
		var tags, created string
		if err := rows.Scan(&t.ID, &t.Value, &t.Type, &tags, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tags), &t.Tags)
		t.CreatedAt = parseTime(created)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) Target(id int64) (types.Target, error) {
	var t types.Target
	var tags, created string
	err := db.QueryRow(`select id,value,type,tags,created_at from targets where id=?`, id).Scan(&t.ID, &t.Value, &t.Type, &tags, &created)
	if err != nil {
		return t, err
	}
	_ = json.Unmarshal([]byte(tags), &t.Tags)
	t.CreatedAt = parseTime(created)
	return t, nil
}

func (db *DB) RemoveTarget(id int64) error {
	_, err := db.Exec(`delete from targets where id=?`, id)
	return err
}

func (db *DB) SetTargetTags(id int64, tags []string) error {
	data, _ := json.Marshal(unique(tags))
	_, err := db.Exec(`update targets set tags=? where id=?`, string(data), id)
	return err
}

func (db *DB) SaveScan(scan types.Scan, services []types.Service, findings []types.Finding) (int64, error) {
	portData, _ := json.Marshal(scan.Ports)
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(`insert into scans(target,profile,ports,status,risk_score,started_at,finished_at,duration_ms,error) values(?,?,?,?,?,?,?,?,?)`,
		scan.Target, scan.Profile, string(portData), scan.Status, scan.RiskScore, scan.StartedAt.Format(time.RFC3339), scan.FinishedAt.Format(time.RFC3339), scan.DurationMS, scan.Error)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	scanID, _ := res.LastInsertId()
	for i := range services {
		services[i].ScanID = scanID
		meta, _ := json.Marshal(services[i].Metadata)
		res, err := tx.Exec(`insert into services(scan_id,port,protocol,service,product,version,banner,metadata_json,created_at) values(?,?,?,?,?,?,?,?,?)`,
			scanID, services[i].Port, services[i].Protocol, services[i].Service, services[i].Product, services[i].Version, services[i].Banner, string(meta), now())
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		svcID, _ := res.LastInsertId()
		for j := range findings {
			if findings[j].ServiceID == services[i].ID || findings[j].ServiceID == 0 && findings[j].Title != "" {
				findings[j].ServiceID = svcID
			}
		}
	}
	for _, f := range findings {
		if f.CreatedAt.IsZero() {
			f.CreatedAt = time.Now()
		}
		_, err := tx.Exec(`insert into findings(scan_id,service_id,title,severity,cvss,cve_id,description,evidence,recommendation,confidence,created_at) values(?,?,?,?,?,?,?,?,?,?,?)`,
			scanID, f.ServiceID, f.Title, f.Severity, f.CVSS, f.CVEID, f.Description, f.Evidence, f.Recommendation, f.Confidence, f.CreatedAt.Format(time.RFC3339))
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	}
	return scanID, tx.Commit()
}

func (db *DB) ListScans() ([]types.Scan, error) {
	rows, err := db.Query(`select id,target,profile,ports,status,risk_score,started_at,finished_at,duration_ms,error from scans order by id desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Scan
	for rows.Next() {
		scan, err := scanFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, scan)
	}
	return out, rows.Err()
}

func (db *DB) Scan(id int64) (types.Scan, []types.Service, []types.Finding, error) {
	row := db.QueryRow(`select id,target,profile,ports,status,risk_score,started_at,finished_at,duration_ms,error from scans where id=?`, id)
	scan, err := scanFromScanner(row)
	if err != nil {
		return scan, nil, nil, err
	}
	services, err := db.Services(id)
	if err != nil {
		return scan, nil, nil, err
	}
	findings, err := db.Findings(id)
	return scan, services, findings, err
}

func (db *DB) DeleteScan(id int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, stmt := range []string{`delete from findings where scan_id=?`, `delete from services where scan_id=?`, `delete from reports where scan_id=?`, `delete from scans where id=?`} {
		if _, err := tx.Exec(stmt, id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) Services(scanID int64) ([]types.Service, error) {
	rows, err := db.Query(`select id,scan_id,port,protocol,service,product,version,banner,metadata_json,created_at from services where scan_id=? order by port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Service
	for rows.Next() {
		var s types.Service
		var meta, created string
		if err := rows.Scan(&s.ID, &s.ScanID, &s.Port, &s.Protocol, &s.Service, &s.Product, &s.Version, &s.Banner, &meta, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(meta), &s.Metadata)
		if s.Metadata == nil {
			s.Metadata = map[string]string{}
		}
		s.CreatedAt = parseTime(created)
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) Findings(scanID int64) ([]types.Finding, error) {
	rows, err := db.Query(`select id,scan_id,service_id,title,severity,cvss,cve_id,description,evidence,recommendation,confidence,created_at from findings where scan_id=? order by severity,title`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Finding
	for rows.Next() {
		var f types.Finding
		var created string
		if err := rows.Scan(&f.ID, &f.ScanID, &f.ServiceID, &f.Title, &f.Severity, &f.CVSS, &f.CVEID, &f.Description, &f.Evidence, &f.Recommendation, &f.Confidence, &created); err != nil {
			return nil, err
		}
		f.CreatedAt = parseTime(created)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (db *DB) ImportCVEs(records []types.CVERecord) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, rec := range records {
		refs, _ := json.Marshal(rec.References)
		_, err := tx.Exec(`insert into cves(cve_id,vendor,product,affected_version,severity,cvss,description,recommendation,references_json) values(?,?,?,?,?,?,?,?,?) on conflict(cve_id) do update set vendor=excluded.vendor, product=excluded.product, affected_version=excluded.affected_version, severity=excluded.severity, cvss=excluded.cvss, description=excluded.description, recommendation=excluded.recommendation, references_json=excluded.references_json`,
			rec.CVEID, rec.Vendor, rec.Product, rec.AffectedVersion, rec.Severity, rec.CVSS, rec.Description, rec.Recommendation, string(refs))
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) CVEs(query string) ([]types.CVERecord, error) {
	q := "%" + strings.ToLower(query) + "%"
	rows, err := db.Query(`select id,cve_id,vendor,product,affected_version,severity,cvss,description,recommendation,references_json from cves where lower(cve_id||' '||vendor||' '||product||' '||affected_version||' '||description) like ? order by cve_id`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.CVERecord
	for rows.Next() {
		var rec types.CVERecord
		var refs string
		if err := rows.Scan(&rec.ID, &rec.CVEID, &rec.Vendor, &rec.Product, &rec.AffectedVersion, &rec.Severity, &rec.CVSS, &rec.Description, &rec.Recommendation, &refs); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(refs), &rec.References)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) AddAudit(action string, metadata any) error {
	data, _ := json.Marshal(metadata)
	_, err := db.Exec(`insert into audit_logs(action,metadata_json,created_at) values(?,?,?)`, action, string(data), now())
	return err
}

func (db *DB) AuditLogs() ([]types.AuditLog, error) {
	rows, err := db.Query(`select id,action,metadata_json,created_at from audit_logs order by id desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.AuditLog
	for rows.Next() {
		var log types.AuditLog
		var created string
		if err := rows.Scan(&log.ID, &log.Action, &log.Metadata, &created); err != nil {
			return nil, err
		}
		log.CreatedAt = parseTime(created)
		out = append(out, log)
	}
	return out, rows.Err()
}

func (db *DB) ClearAudit() error {
	_, err := db.Exec(`delete from audit_logs`)
	return err
}

func (db *DB) AddReport(scanID int64, format, path string) error {
	_, err := db.Exec(`insert into reports(scan_id,format,path,created_at) values(?,?,?,?)`, scanID, format, path, now())
	return err
}

func (db *DB) Stats() (map[string]int, error) {
	out := map[string]int{}
	for _, table := range []string{"targets", "scans", "services", "findings", "cves", "audit_logs", "reports"} {
		var count int
		if err := db.QueryRow(`select count(*) from ` + table).Scan(&count); err != nil {
			return nil, err
		}
		out[table] = count
	}
	return out, nil
}

func (db *DB) Vacuum() error {
	_, err := db.Exec(`vacuum`)
	return err
}

func (db *DB) Backup(out string) error {
	src, err := os.Open(db.Path)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil && filepath.Dir(out) != "." {
		return err
	}
	dst, err := os.Create(out)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

func (db *DB) Restore(path string) error {
	if err := db.Close(); err != nil {
		return err
	}
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(db.Path)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

type scannerRow interface {
	Scan(dest ...any) error
}

func scanFromRows(rows *sql.Rows) (types.Scan, error) { return scanFromScanner(rows) }

func scanFromScanner(row scannerRow) (types.Scan, error) {
	var scan types.Scan
	var ports, started, finished string
	err := row.Scan(&scan.ID, &scan.Target, &scan.Profile, &ports, &scan.Status, &scan.RiskScore, &started, &finished, &scan.DurationMS, &scan.Error)
	if err != nil {
		return scan, err
	}
	_ = json.Unmarshal([]byte(ports), &scan.Ports)
	scan.StartedAt = parseTime(started)
	scan.FinishedAt = parseTime(finished)
	return scan, nil
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func now() string { return time.Now().Format(time.RFC3339) }

func parseTime(raw string) time.Time {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return t
}

func RequireRowsAffected(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s not found", what)
	}
	return nil
}
