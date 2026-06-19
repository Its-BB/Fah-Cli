package audit

import "fahscan/internal/database"

func Log(db *database.DB, action string, metadata any) {
	if db != nil {
		_ = db.AddAudit(action, metadata)
	}
}
