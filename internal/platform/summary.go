package platform

import "database/sql"

// HospitalSummary 医院级风险汇总（M8-4）。
type HospitalSummary struct {
	HospitalID     string `json:"hospital_id"`
	Assets         int    `json:"assets"`
	Bundles        int    `json:"bundles"`
	FailTotal      int    `json:"fail_total"`
	FailOpen       int    `json:"fail_open"` // FAIL 且未复核处理
	UnknownTotal   int    `json:"unknown_total"`
	CorrPaths      int    `json:"corr_paths"`
	LastBundleAt   string `json:"last_bundle_at"`
}

// HospitalSummaries 按医院聚合资产/包/问题/关联路径。
func HospitalSummaries(db *sql.DB) ([]HospitalSummary, error) {
	byID := map[string]*HospitalSummary{}
	var order []string
	get := func(id string) *HospitalSummary {
		if s, ok := byID[id]; ok {
			return s
		}
		s := &HospitalSummary{HospitalID: id}
		byID[id] = s
		order = append(order, id)
		return s
	}
	rows, err := db.Query(
		`SELECT hospital_id, COUNT(DISTINCT asset_id), COUNT(*), COALESCE(MAX(imported_at), '')
		 FROM fact_bundles GROUP BY hospital_id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, last string
		var assets, bundles int
		if err := rows.Scan(&id, &assets, &bundles, &last); err != nil {
			rows.Close()
			return nil, err
		}
		s := get(id)
		s.Assets, s.Bundles, s.LastBundleAt = assets, bundles, last
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	frows, err := db.Query(
		`SELECT b.hospital_id, f.conclusion, COUNT(*),
		        SUM(CASE WHEN f.conclusion = 'FAIL' AND f.review_status = 'pending' THEN 1 ELSE 0 END)
		 FROM findings f JOIN fact_bundles b ON b.id = f.bundle_id
		 GROUP BY b.hospital_id, f.conclusion`)
	if err != nil {
		return nil, err
	}
	for frows.Next() {
		var id, concl string
		var n, open int
		if err := frows.Scan(&id, &concl, &n, &open); err != nil {
			frows.Close()
			return nil, err
		}
		s := get(id)
		switch concl {
		case "FAIL":
			s.FailTotal += n
			s.FailOpen += open
		case "UNKNOWN":
			s.UnknownTotal += n
		}
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return nil, err
	}

	crows, err := db.Query(
		`SELECT hospital_id, COALESCE(SUM(path_count), 0) FROM correlation_reports GROUP BY hospital_id`)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var id string
		var n int
		if err := crows.Scan(&id, &n); err != nil {
			crows.Close()
			return nil, err
		}
		get(id).CorrPaths = n
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return nil, err
	}

	out := []HospitalSummary{}
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}
