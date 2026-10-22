package platform

import (
	"database/sql"

	"medaudit/internal/rules"
)

// EffectiveEntry 一个主体的有效权限（传递闭包结果）。
type EffectiveEntry struct {
	Subject    string           `json:"subject"`
	IsRole     bool             `json:"is_role"`
	Roles      []rules.RolePath `json:"roles"`
	Privileges []rules.EffPriv  `json:"privileges"`
}

// BundleEffective 计算事实包内全部主体的有效角色与权限（M8-2）。
func BundleEffective(db *sql.DB, bundleID string) ([]EffectiveEntry, error) {
	b, err := loadBundle(db, bundleID)
	if err != nil {
		return nil, err
	}
	ix := rules.BuildEffectiveIndex(b.Facts)
	out := []EffectiveEntry{}
	for _, subj := range ix.Subjects() {
		roles := ix.RolesOf(subj)
		if roles == nil {
			roles = []rules.RolePath{}
		}
		privs := ix.PrivilegesOf(subj)
		if privs == nil {
			privs = []rules.EffPriv{}
		}
		out = append(out, EffectiveEntry{
			Subject: subj, IsRole: ix.IsRole(subj),
			Roles: roles, Privileges: privs,
		})
	}
	return out, nil
}
