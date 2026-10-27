// medaudit-server: MedAudit 管理服务入口（M6：Web 工作台补齐；平台库 SQLite；含证据加密存储）。
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"medaudit/internal/facts"
	"medaudit/internal/license"
	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

const version = "0.35.0-m35"

var authSessions *platform.SessionStore

var scheduler *platform.Scheduler

func main() {
	webDir := flag.String("web-dir", "web/dist", "前端构建产物目录")
	addr := flag.String("addr", "127.0.0.1:8080", "监听地址")
	ver := flag.Bool("V", false, "打印版本信息并退出")
	flag.Parse()
	if *ver {
		fmt.Print(license.VersionBlock("medaudit-server", version, time.Now()))
		return
	}
	if license.Edition == "licensed" {
		st := license.Evaluate(time.Now())
		if st.Usable && st.File != nil {
			fmt.Printf("授权版：授权给 %s（有效期至 %s）\n", st.File.Licensee, st.Expires)
		} else {
			fmt.Printf("授权版：许可证不可用（%s），审计执行将被拦截\n", license.ReasonString(st.Reason))
		}
	}

	var db *sql.DB
	if dbPath := os.Getenv("MEDAUDIT_PLATFORM_DB"); dbPath != "" {
		var err error
		db, err = platform.Open(dbPath)
		if err != nil {
			fmt.Println("平台库打开失败:", err)
			os.Exit(1)
		}
		defer db.Close()
		if err := db.Ping(); err != nil {
			fmt.Println("平台库 Ping 失败:", err)
			os.Exit(1)
		}
		if err := platform.Migrate(db); err != nil {
			fmt.Println("平台库迁移失败:", err)
			os.Exit(1)
		}
		initSiteHospital(db)
		fmt.Println("平台库已连接（SQLite）:", dbPath)
	} else {
		fmt.Println("警告：未设置 MEDAUDIT_PLATFORM_DB，数据接口将返回 503")
	}

	// 证据加密密钥环（M4-3b）：装配失败直接退出，避免静默降级为不加密。
	var keyring *platform.EvidenceKeyring
	if db != nil {
		var err error
		keyring, err = platform.LoadEvidenceKeyringFromEnv()
		if err != nil {
			fmt.Println("证据密钥装配失败:", err)
			os.Exit(1)
		}
		if keyring != nil {
			fmt.Printf("证据加密已启用（密钥版本 v%d）\n", keyring.CurrentVersion())
		} else {
			fmt.Println("警告：未配置 MEDAUDIT_EVIDENCE_KEY，证据加密存储未启用")
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "version": version})
	})
	mux.HandleFunc("/api/v1/admin/backup", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			http.Error(w, "平台库未配置", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path, err := platform.BackupSnapshot(db, os.TempDir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(path)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=medaudit-platform-backup.db")
		http.ServeFile(w, r, path)
	})
	mux.HandleFunc("/api/v1/assets", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			http.Error(w, "平台库未配置", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			assets, err := platform.ListAssets(db)
			if err != nil {
				http.Error(w, "查询资产失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, assets)
		case http.MethodPost:
			var a platform.Asset
			if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			if err := platform.CreateAsset(db, a); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]string{"status": "ok", "id": a.ID})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// 事实包导入：POST zip → 校验 → 去重 → 落库
	mux.HandleFunc("/api/v1/bundles", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			http.Error(w, "平台库未配置", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodPost:
			importBundle(w, r, db, keyring)
		case http.MethodGet:
			listBundles(w, r, db)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// 证据下载：GET /api/v1/bundles/{id}/evidence → 解密返回原始 zip 并复核摘要
	mux.HandleFunc("/api/v1/bundles/", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			http.Error(w, "平台库未配置", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/bundles/")
		if strings.HasSuffix(rest, "/facts") {
			fid := strings.TrimSuffix(rest, "/facts")
			if fid == "" || strings.Contains(fid, "/") {
				http.NotFound(w, r)
				return
			}
			q := r.URL.Query()
			limit, _ := strconv.Atoi(q.Get("limit"))
			offset, _ := strconv.Atoi(q.Get("offset"))
			page, err := platform.BundleFacts(db, fid, q.Get("kind"), offset, limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, page)
			return
		}
		if strings.HasSuffix(rest, "/effective") {
			eid := strings.TrimSuffix(rest, "/effective")
			if eid == "" || strings.Contains(eid, "/") {
				http.NotFound(w, r)
				return
			}
			entries, err := platform.BundleEffective(db, eid)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, entries)
			return
		}
		if strings.HasSuffix(rest, "/drift") {
			did := strings.TrimSuffix(rest, "/drift")
			against := r.URL.Query().Get("against")
			if did == "" || strings.Contains(did, "/") || against == "" {
				http.Error(w, "需要 ?against=<另一事实包ID>", http.StatusBadRequest)
				return
			}
			rep, err := platform.BundleDrift(db, against, did)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, rep)
			return
		}
		if !strings.Contains(rest, "/") {
			detail, err := platform.BundleDetailByID(db, rest)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, detail)
			return
		}
		if !strings.HasSuffix(rest, "/evidence") {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimSuffix(rest, "/evidence")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		zipBytes, digest, err := platform.FetchEvidence(db, keyring, id)
		if errors.Is(err, platform.ErrEvidenceNotFound) {
			http.Error(w, "该事实包无存档证据（可能为证据功能启用前导入）", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "证据读取失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename="+id+".zip")
		w.Header().Set("X-Evidence-SHA256", digest)
		w.Write(zipBytes)
	})

	// 评估/基线/复核/规则路由
	if db != nil {
		registerEvalRoutes(mux, db, rules.DefaultRegistry())
		registerAPIAuditRoutes(mux, db)
		registerReportReadRoutes(mux, db)
		collectorBin := os.Getenv("MEDAUDIT_COLLECTOR_BIN")
		if collectorBin == "" {
			if exe, err := os.Executable(); err == nil {
				cand := filepath.Join(filepath.Dir(exe), "medaudit-collector")
				if _, err := os.Stat(cand); err == nil {
					collectorBin = cand
				}
			}
		}
		if collectorBin != "" {
			fmt.Fprintf(os.Stderr, "一键审计已启用（采集器: %s）\n", collectorBin)
		} else {
			fmt.Fprintln(os.Stderr, "一键审计未启用（未找到采集器，可设 MEDAUDIT_COLLECTOR_BIN）")
		}
		registerM6Routes(mux, db, rules.DefaultRegistry(), keyring, collectorBin)
		registerCorrelationRoutes(mux, db)
		registerSummaryRoutes(mux, db)
		registerSiteRoutes(mux, db)
		registerRuleToggleRoutes(mux, db, rules.DefaultRegistry())
		// M9 远程推送：Windows 采集器路径（env 优先，否则同目录 medaudit-collector.exe）
		collectorWinBin := os.Getenv("MEDAUDIT_COLLECTOR_WIN_BIN")
		if collectorWinBin == "" {
			if exe, err := os.Executable(); err == nil {
				cand := filepath.Join(filepath.Dir(exe), "medaudit-collector.exe")
				if _, err := os.Stat(cand); err == nil {
					collectorWinBin = cand
				}
			}
		}
		tokens := platform.NewTokenStore()
		registerRemoteRoutes(mux, db, rules.DefaultRegistry(), keyring, collectorBin, collectorWinBin, tokens)
		// 定期自动复检：与一键审计/远程推送共用执行实现。
		scheduler = platform.NewScheduler(db, rules.DefaultRegistry(), keyring, collectorBin, collectorBin, collectorWinBin, tokens)
		scheduler.Start(context.Background())
		// M12 登录鉴权：播种默认管理员（仅用户表为空时）+ 会话与 auth 路由
		if err := platform.SeedDefaultAdmin(db); err != nil {
			fmt.Fprintf(os.Stderr, "默认管理员播种失败: %v\n", err)
		}
		sessions := platform.NewSessionStore()
		registerAuthRoutes(mux, db, sessions)
		registerUserRoutes(mux, db, sessions) // M20 用户管理
		registerAdminRoutes(mux, db, sessions) // M27 一键清场
		registerOpLogRoutes(mux, db)           // 平台操作日志
		registerAlertRoutes(mux, db, sessions) // 权限漂移/复检失败告警
		registerScheduleRoutes(mux, db, keyring, scheduler, sessions)
		authSessions = sessions
		if collectorWinBin != "" {
			fmt.Fprintf(os.Stderr, "远程推送（WinRM）已启用（Windows 采集器: %s）\n", collectorWinBin)
		}
	}

	// 静态前端：web/dist；SPA 回退到 index.html。
	if st, err := os.Stat(*webDir); err == nil && st.IsDir() {
		mux.Handle("/", spaHandler(*webDir))
		fmt.Println("前端目录:", *webDir)
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "medaudit-server "+version+"（前端未构建：web/dist 不存在）")
		})
	}

	fmt.Printf("medaudit-server %s listening on %s\n", version, *addr)
	handler := http.Handler(mux)
	if authSessions != nil {
		handler = opLogMiddleware(authMiddleware(mux, authSessions), db, authSessions)
	}
	if err := http.ListenAndServe(*addr, handler); err != nil {
		fmt.Println("server stopped:", err)
	}
}

func importBundle(w http.ResponseWriter, r *http.Request, db *sql.DB, kr *platform.EvidenceKeyring) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 100<<20))
	if err != nil {
		http.Error(w, "读取请求失败", http.StatusBadRequest)
		return
	}
	b, err := facts.ReadZipBytes(data)
	if err != nil {
		http.Error(w, "事实包解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	err = platform.ImportBundle(db, b, data, kr)
	if errors.Is(err, platform.ErrDuplicateBundle) {
		writeJSON(w, map[string]any{
			"bundle_id": b.BundleID, "status": "duplicate",
			"facts": len(b.Facts), "receipts": len(b.Receipts),
		})
		return
	}
	if err != nil {
		http.Error(w, "导入失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{
		"bundle_id": b.BundleID, "status": "imported",
		"facts": len(b.Facts), "receipts": len(b.Receipts),
	})
}

func listBundles(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	summaries, err := platform.ListBundles(db)
	if err != nil {
		http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, summaries)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// spaHandler 静态文件服务，不存在时回退 index.html。
func spaHandler(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(dir, filepath.Clean(r.URL.Path))
		if st, err := os.Stat(p); err != nil || st.IsDir() || p == dir {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	})
}
