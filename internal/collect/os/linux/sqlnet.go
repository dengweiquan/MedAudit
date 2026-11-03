package linux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"medaudit/internal/facts"
)

// collectOracleSqlnet 采集宿主 Oracle 各 Home 的 sqlnet.ora 原生网络加密策略（linux.oracle_sqlnet v1）。
// dir 为 etc 根目录（与 sudoers 共用缺省 /etc），oratab 位于 <dir>/oratab；Home 路径取 oratab 绝对路径。
// 本节只读宿主本机文件（采集器在宿主本地执行），绝不读采集器本机客户端配置。
// 每 Home 独立出事实；无 Home 时出盘点事实（规则 NA）；单 Home 失败不掩盖其他 Home 的结论。
func collectOracleSqlnet(b *facts.FactBundle, dir string, addReceipt func(facts.Receipt), execStatus *facts.ExecutionStatus) {
	rStart := time.Now()
	receipt := facts.Receipt{
		TemplateID: "linux.oracle_sqlnet", TemplateVersion: "1",
		Started: rStart.UTC().Truncate(time.Second),
		Status:  "ok", Visibility: "full",
	}
	finish := func() {
		receipt.Finished = time.Now().UTC().Truncate(time.Second)
		receipt.DurationMs = receipt.Finished.Sub(receipt.Started).Milliseconds()
		addReceipt(receipt)
	}
	if dir == "" {
		dir = "/etc"
	}
	oratabPath := filepath.Join(dir, "oratab")
	raw, err := os.ReadFile(oratabPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 无 oratab 即宿主无 Oracle 登记：盘点事实，规则 NA，不算失败。
			b.Facts = append(b.Facts, facts.Fact{
				FactID: "fact-sqlnet-nohome", Kind: facts.FactAccountConfig,
				Subject: "oracle-homes", Status: facts.StatusObserved, Source: "linux.oracle_sqlnet",
				Attributes: map[string]string{"oracle_homes": "0"},
			})
			receipt.RowCount = 0
			finish()
			return
		}
		receipt.Status = "failed"
		receipt.ErrorStage = "read"
		receipt.Error = facts.RedactSecrets(err.Error())
		b.Facts = append(b.Facts, facts.Fact{
			FactID: "fact-sqlnet-oratab-denied", Kind: facts.FactAccountConfig,
			Subject: "oratab", Status: facts.StatusPermissionDenied, Source: "linux.oracle_sqlnet",
			Attributes: map[string]string{"error": facts.RedactSecrets(err.Error()), "file": oratabPath},
		})
		*execStatus = facts.ExecutionPartial
		finish()
		return
	}
	homes := ParseOratab(raw)
	if len(homes) == 0 {
		b.Facts = append(b.Facts, facts.Fact{
			FactID: "fact-sqlnet-nohome", Kind: facts.FactAccountConfig,
			Subject: "oracle-homes", Status: facts.StatusObserved, Source: "linux.oracle_sqlnet",
			Attributes: map[string]string{"oracle_homes": "0"},
		})
		receipt.RowCount = 0
		finish()
		return
	}
	seq := 0
	partial := false
	var firstErr string
	for _, h := range homes {
		seq++
		// TNS_ADMIN 本期不从采集器环境取（那是客户端配置）；只用 Home 缺省路径。
		// 实例级 TNS_ADMIN 可靠已知时再传 LocateSqlnetOra 的第二个参数。
		sqlnetPath := LocateSqlnetOra(h.Home, "")
		attrs := map[string]string{
			"oracle_home": h.Home, "sid": h.SID, "sqlnet_file": sqlnetPath,
		}
		params, chain, rerr := ResolveSqlnetOra(os.ReadFile, sqlnetPath)
		switch {
		case rerr != nil && errors.Is(rerr, ErrSqlnetEntryMissing):
			// 入口文件本身缺失 → Oracle 缺省 accepted（事实标注 file_missing，规则按缺省值判）。
			// 链内 IFILE 缺失不进此分支（其错误不满足 ErrSqlnetEntryMissing），
			// 即使同样是文件不存在也不得猜默认值，须走下方的解析失败分支。
			attrs["encryption_server"] = "accepted"
			attrs["file_missing"] = "true"
			b.Facts = append(b.Facts, facts.Fact{
				FactID: fmt.Sprintf("fact-sqlnet-%d", seq), Kind: facts.FactAccountConfig,
				Subject: h.Home, Status: facts.StatusObserved, Source: "linux.oracle_sqlnet",
				Attributes: attrs,
			})
		case rerr != nil && os.IsPermission(rerr):
			b.Facts = append(b.Facts, facts.Fact{
				FactID: fmt.Sprintf("fact-sqlnet-%d", seq), Kind: facts.FactAccountConfig,
				Subject: h.Home, Status: facts.StatusPermissionDenied, Source: "linux.oracle_sqlnet",
				Attributes: map[string]string{
					"oracle_home": h.Home, "sid": h.SID, "sqlnet_file": sqlnetPath,
					"error": facts.RedactSecrets(rerr.Error()),
				},
			})
			partial = true
			if firstErr == "" {
				firstErr = rerr.Error()
			}
		case rerr != nil:
			// IFILE 环/超深/其他读错：参数不可信，不出 Observed 事实，只留档说明。
			b.Facts = append(b.Facts, facts.Fact{
				FactID: fmt.Sprintf("fact-sqlnet-%d", seq), Kind: facts.FactAccountConfig,
				Subject: h.Home, Status: facts.StatusUnsupported, Source: "linux.oracle_sqlnet",
				Attributes: map[string]string{
					"oracle_home": h.Home, "sid": h.SID, "sqlnet_file": sqlnetPath,
					"error": facts.RedactSecrets(rerr.Error()),
				},
			})
			partial = true
			if firstErr == "" {
				firstErr = rerr.Error()
			}
		default:
			// 参数缺失同样取 Oracle 缺省 accepted（与文件缺失同理，标注 param_missing）。
			enc := params["SQLNET.ENCRYPTION_SERVER"]
			if enc == "" {
				enc = "accepted"
				attrs["param_missing"] = "true"
			}
			attrs["encryption_server"] = enc
			if v := params["SQLNET.ENCRYPTION_TYPES_SERVER"]; v != "" {
				attrs["encryption_types_server"] = v
			}
			attrs["ifile_chain"] = strings.Join(chain, ",")
			b.Facts = append(b.Facts, facts.Fact{
				FactID: fmt.Sprintf("fact-sqlnet-%d", seq), Kind: facts.FactAccountConfig,
				Subject: h.Home, Status: facts.StatusObserved, Source: "linux.oracle_sqlnet",
				Attributes: attrs,
			})
		}
		receipt.RowCount++
	}
	if partial {
		receipt.Status = "partial"
		receipt.ErrorStage = "read"
		receipt.Error = facts.RedactSecrets(firstErr)
		*execStatus = facts.ExecutionPartial
	}
	finish()
}
