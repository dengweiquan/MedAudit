package mysql

import "testing"

func TestParseShowGrant(t *testing.T) {
	cases := []struct {
		name      string
		stmt      string
		wantUser  string
		wantHost  string
		isRole    bool
		isRevoke  bool
		wantPrivs []string
		wantScope string
		wantGrant bool
		wantRoles []string
	}{
		{
			name:      "global privs backtick",
			stmt:      "GRANT SELECT, INSERT, UPDATE, DELETE ON *.* TO `medaudit_pr`@`%`",
			wantUser:  "medaudit_pr",
			wantHost:  "%",
			wantPrivs: []string{"SELECT", "INSERT", "UPDATE", "DELETE"},
			wantScope: "*.*",
		},
		{
			name:      "partial revoke",
			stmt:      "REVOKE INSERT, UPDATE, DELETE ON `medaudit_testdb`.* FROM `medaudit_pr`@`%`",
			wantUser:  "medaudit_pr",
			wantHost:  "%",
			isRevoke:  true,
			wantPrivs: []string{"INSERT", "UPDATE", "DELETE"},
			wantScope: "medaudit_testdb.*",
		},
		{
			name:      "usage",
			stmt:      "GRANT USAGE ON *.* TO `medaudit_app`@`%`",
			wantUser:  "medaudit_app",
			wantHost:  "%",
			wantPrivs: []string{"USAGE"},
			wantScope: "*.*",
		},
		{
			name:      "db privs with grant option",
			stmt:      "GRANT SELECT, INSERT ON `medaudit_testdb`.* TO `medaudit_app`@`%` WITH GRANT OPTION",
			wantUser:  "medaudit_app",
			wantHost:  "%",
			wantPrivs: []string{"SELECT", "INSERT"},
			wantScope: "medaudit_testdb.*",
			wantGrant: true,
		},
		{
			name:      "role grant backtick list",
			stmt:      "GRANT `medaudit_r_extra`@`%`,`medaudit_r_read`@`%` TO `medaudit_app`@`%`",
			wantUser:  "medaudit_app",
			wantHost:  "%",
			isRole:    true,
			wantRoles: []string{"medaudit_r_extra@%", "medaudit_r_read@%"},
		},
		{
			name:      "single quotes",
			stmt:      "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION",
			wantUser:  "root",
			wantHost:  "localhost",
			wantPrivs: []string{"ALL PRIVILEGES"},
			wantScope: "*.*",
			wantGrant: true,
		},
		{
			name:      "table scope",
			stmt:      "GRANT SELECT ON `mydb`.`mytbl` TO 'u'@'h'",
			wantUser:  "u",
			wantHost:  "h",
			wantPrivs: []string{"SELECT"},
			wantScope: "mydb.mytbl",
		},
		{
			name:      "revoke all without ON",
			stmt:      "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'u'@'h'",
			wantUser:  "u",
			wantHost:  "h",
			isRevoke:  true,
			wantPrivs: []string{"ALL PRIVILEGES", "GRANT OPTION"},
			wantScope: "*.*",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, err := ParseShowGrant(c.stmt)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if g.GranteeUser != c.wantUser || g.GranteeHost != c.wantHost {
				t.Fatalf("grantee = %s@%s, want %s@%s", g.GranteeUser, g.GranteeHost, c.wantUser, c.wantHost)
			}
			if g.IsRoleGrant != c.isRole {
				t.Fatalf("IsRoleGrant = %v, want %v", g.IsRoleGrant, c.isRole)
			}
			if g.IsRevoke != c.isRevoke {
				t.Fatalf("IsRevoke = %v, want %v", g.IsRevoke, c.isRevoke)
			}
			if c.isRole {
				if len(g.Roles) != len(c.wantRoles) {
					t.Fatalf("roles = %v, want %v", g.Roles, c.wantRoles)
				}
				for i, r := range g.Roles {
					if r.String() != c.wantRoles[i] {
						t.Fatalf("role[%d] = %s, want %s", i, r, c.wantRoles[i])
					}
				}
				return
			}
			if len(g.Privs) != len(c.wantPrivs) {
				t.Fatalf("privs = %v, want %v", g.Privs, c.wantPrivs)
			}
			for i, p := range g.Privs {
				if p != c.wantPrivs[i] {
					t.Fatalf("priv[%d] = %q, want %q", i, p, c.wantPrivs[i])
				}
			}
			if g.Scope != c.wantScope {
				t.Fatalf("scope = %q, want %q", g.Scope, c.wantScope)
			}
			if g.WithGrantOption != c.wantGrant {
				t.Fatalf("WithGrantOption = %v, want %v", g.WithGrantOption, c.wantGrant)
			}
		})
	}
}
