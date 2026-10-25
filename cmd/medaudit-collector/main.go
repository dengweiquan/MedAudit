// medaudit-collector: 一次性采集器。
//
// medaudit-collector os --plan <id> --out <bundle.zip> [--services a.service,b.service]
// medaudit-collector db --engine <oracle|sqlserver|mysql|postgres> --config <file.yml> --out <bundle.zip>
// medaudit-collector bundle verify --file <bundle.zip>
// medaudit-collector bundle upload --file <bundle.zip> --server <url>
//
// 配置文件中的密码一律用 password_env 指向环境变量，不接受明文密码。
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"medaudit/internal/collect/db/mysql"
	"medaudit/internal/collect/db/oracle"
	"medaudit/internal/collect/db/postgres"
	"medaudit/internal/collect/db/sqlserver"
	"medaudit/internal/collect/mw"
	"medaudit/internal/facts"
	"medaudit/internal/license"
)

const version = "0.34.0-m34"

// splitPos 让 flag 与位置参数可交错：反复 Parse 并逐个取走位置参数。
func splitPos(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// resolveHospital 医院缺省链：显式旗标 > 环境 MEDAUDIT_HOSPITAL > 内置缺省。
func resolveHospital(v, def string) string {
	if v != "" {
		return v
	}
	if e := os.Getenv("MEDAUDIT_HOSPITAL"); e != "" {
		return e
	}
	return def
}

// autoBundleName 缺省输出名：bundle-<类>-<UTC时间>.zip。
func autoBundleName(kind string) string {
	return fmt.Sprintf("bundle-%s-%s.zip", kind, time.Now().UTC().Format("20060102-150405"))
}

// gateCheck 授权版门控：采集产包（产生新数据）前调用；
// 免费版直接放行，提醒打印到 stderr，不可用返回拦截文案。
func gateCheck() error {
	warns, err := license.Gate(time.Now())
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, w)
	}
	return err
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "os", "hpux", "mw", "apicheck":
		if err := gateCheck(); err != nil {
			fmt.Fprintln(os.Stderr, "错误:", err)
			os.Exit(1)
		}
	}
	var err error
	switch os.Args[1] {
	case "os":
		err = runOS(os.Args[2:])
	case "hpux":
		err = runHpux(os.Args[2:])
	case "db":
		err = runDB(os.Args[2:])
	case "mw":
		err = runMW(os.Args[2:])
	case "apicheck":
		err = runAPICheck(os.Args[2:])
	case "bundle":
		err = runBundle(os.Args[2:])
	case "version", "-v", "--version", "-V":
		fmt.Print(license.VersionBlock("medaudit-collector", version, time.Now()))
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, errPreflightPartial) {
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(`medaudit-collector %s（M23 简化参数：位置参数 + 短旗标，医院可用环境 MEDAUDIT_HOSPITAL 缺省）
用法：
  medaudit-collector os [资产id] [-o 输出.zip] [-s a.service,b.service] [-H 医院] [-p 计划]
  medaudit-collector db -f <配置.yml> [-o 输出.zip] [-P 预检]（引擎取配置内 engine，-e 可覆盖）
  medaudit-collector mw <tomcat|nginx|weblogic|iis> [目录] [资产id] [-o 输出.zip] [-H 医院]
  medaudit-collector hpux <user@host[:port]> [资产id] [-e 口令环境变量] [-o 输出.zip] [-H 医院]
  medaudit-collector hpux -t <转录目录> [资产id] [-o 输出.zip] [-H 医院]
  medaudit-collector apicheck -f <配置.yml> [-o 报告.json] [-u 上传地址]（缺省读环境 MEDAUDIT_SERVER）
  medaudit-collector bundle verify <文件.zip>
  medaudit-collector bundle upload <文件.zip> [服务地址]
长旗标（--out/--hospital/--config/--upload 等）继续可用，与短旗标等价。
`, version)
}

// ---------- os ----------

func runOS(args []string) error {
	fs := flag.NewFlagSet("os", flag.ContinueOnError)
	var out, plan, services, hospital, asset, sudoersDir string
	fs.StringVar(&out, "o", "", "输出事实包路径（缺省自动命名）")
	fs.StringVar(&out, "out", "", "同 -o")
	fs.StringVar(&plan, "p", "plan-m1-os", "采集计划 ID")
	fs.StringVar(&plan, "plan", "plan-m1-os", "同 -p")
	fs.StringVar(&services, "s", "", "systemd 单元，逗号分隔（缺省自动枚举）")
	fs.StringVar(&services, "services", "", "同 -s")
	fs.StringVar(&hospital, "H", "", "医院 ID（缺省环境 MEDAUDIT_HOSPITAL）")
	fs.StringVar(&hospital, "hospital", "", "同 -H")
	fs.StringVar(&asset, "asset", "", "资产 ID（或第一个位置参数）")
	fs.StringVar(&sudoersDir, "sudoers-dir", "", "sudoers 根目录（默认 /etc；离线根目录可指定）")
	pos, err := splitPos(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		asset = pos[0]
	}
	if asset == "" {
		asset = "host-local"
	}
	if out == "" {
		out = autoBundleName("os-linux")
	}
	hospital = resolveHospital(hospital, "h-m1-test")
	var svcs []string
	if services != "" {
		svcs = strings.Split(services, ",")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	b, err := collectOS(ctx, hospital, asset, plan, svcs, sudoersDir)
	if err != nil {
		return err
	}
	if err := facts.WriteZip(out, b); err != nil {
		return err
	}
	fmt.Printf("OS 采集完成：%d facts, %d receipts, %s → %s\n",
		len(b.Facts), len(b.Receipts), b.Execution, out)
	return nil
}

// ---------- db ----------

// DBFileConfig 数据库采集配置文件（YAML）。密码只接受环境变量引用。
type DBFileConfig struct {
	Engine         string `yaml:"engine"`
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	User           string `yaml:"user"`
	PasswordEnv    string `yaml:"password_env"`
	DBName         string `yaml:"dbname"`
	Service        string `yaml:"service"`
	SSLMode        string `yaml:"sslmode"`
	ConnectTimeout string `yaml:"connect_timeout"`
	QueryTimeout   string `yaml:"query_timeout"`
	HospitalID     string `yaml:"hospital_id"`
	AssetID        string `yaml:"asset_id"`
	PlanID         string `yaml:"plan_id"`
}

func runDB(args []string) error {
	fs := flag.NewFlagSet("db", flag.ContinueOnError)
	var engine, configPath, out string
	var preflight bool
	fs.StringVar(&engine, "e", "", "oracle|sqlserver|mysql|postgres（缺省取配置内 engine）")
	fs.StringVar(&engine, "engine", "", "同 -e")
	fs.StringVar(&configPath, "f", "", "连接配置文件（YAML）")
	fs.StringVar(&configPath, "config", "", "同 -f")
	fs.BoolVar(&preflight, "P", false, "预检模式：只打印逐模板收据与完整性结论，不落事实包（退出码 0 完整 / 3 不完整 / 1 失败）")
	fs.BoolVar(&preflight, "preflight", false, "同 -P")
	fs.StringVar(&out, "o", "", "输出事实包路径（缺省自动命名）")
	fs.StringVar(&out, "out", "", "同 -o")
	pos, err := splitPos(fs, args)
	if err != nil {
		return err
	}
	if !preflight {
		if err := gateCheck(); err != nil {
			return err
		}
	}
	if configPath == "" && len(pos) > 0 {
		configPath = pos[0]
	}
	if configPath == "" {
		return fmt.Errorf("用法：db -f <配置.yml> [-o 输出.zip] [-P 预检]")
	}
	cfg, err := loadDBConfig(configPath)
	if err != nil {
		return err
	}
	if engine == "" {
		engine = cfg.Engine
	}
	if engine == "" {
		return fmt.Errorf("引擎未知：配置内 engine 为空且未用 -e 指定")
	}
	if cfg.Engine != "" && cfg.Engine != engine {
		return fmt.Errorf("配置文件 engine=%s 与 -e %s 不一致", cfg.Engine, engine)
	}
	password := os.Getenv(cfg.PasswordEnv)
	if cfg.PasswordEnv != "" && password == "" {
		return fmt.Errorf("环境变量 %s 未设置", cfg.PasswordEnv)
	}
	connTimeout := parseDur(cfg.ConnectTimeout, 15*time.Second)
	queryTimeout := parseDur(cfg.QueryTimeout, 30*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var b *facts.FactBundle
	switch engine {
	case "mysql":
		b, err = mysql.Collect(ctx, mysql.Config{
			Host: cfg.Host, Port: cfg.Port, User: cfg.User, Password: password,
			DBName: cfg.DBName, ConnectTimeout: connTimeout, QueryTimeout: queryTimeout,
		})
	case "sqlserver":
		b, err = sqlserver.Collect(ctx, sqlserver.Config{
			Host: cfg.Host, Port: cfg.Port, User: cfg.User, Password: password,
			DBName: cfg.DBName, ConnectTimeout: connTimeout, QueryTimeout: queryTimeout,
		})
	case "oracle":
		b, err = oracle.Collect(ctx, oracle.Config{
			Host: cfg.Host, Port: cfg.Port, Service: cfg.Service, User: cfg.User,
			Password: password, ConnectTimeout: connTimeout, QueryTimeout: queryTimeout,
		})
	case "postgres":
		b, err = postgres.Collect(ctx, postgres.Config{
			Host: cfg.Host, Port: cfg.Port, User: cfg.User, Password: password,
			DBName: cfg.DBName, SSLMode: cfg.SSLMode, ConnectTimeout: connTimeout, QueryTimeout: queryTimeout,
		})
	default:
		return fmt.Errorf("不支持的 engine: %s", engine)
	}
	if err != nil {
		return fmt.Errorf("采集失败: %w", err)
	}
	// 覆盖身份与计划信息
	if cfg.HospitalID != "" {
		b.Scope.HospitalID = cfg.HospitalID
	}
	if cfg.AssetID != "" {
		b.Scope.AssetID = cfg.AssetID
	}
	if cfg.PlanID != "" {
		b.PlanID = cfg.PlanID
	}
	if errs := b.Validate(); len(errs) != 0 {
		return fmt.Errorf("事实包校验失败: %v", errs)
	}
	if preflight {
		return printPreflight(b, cfg)
	}
	if out == "" {
		out = autoBundleName(engine)
	}
	if err := facts.WriteZip(out, b); err != nil {
		return err
	}
	fmt.Printf("DB 采集完成 [%s]：%d facts, %d receipts, %s → %s\n",
		engine, len(b.Facts), len(b.Receipts), b.Execution, out)
	return nil
}

// ---------- mw ----------

func runMW(args []string) error {
	fs := flag.NewFlagSet("mw", flag.ContinueOnError)
	var typ, home, out, plan, hospital, asset string
	fs.StringVar(&typ, "type", "", "tomcat|nginx|weblogic|iis（或第一个位置参数）")
	fs.StringVar(&home, "home", "", "Tomcat: CATALINA_HOME；Nginx: 配置目录；WebLogic: 域根目录；IIS: 配置路径（或第二个位置参数）")
	fs.StringVar(&out, "o", "", "输出事实包路径（缺省自动命名）")
	fs.StringVar(&out, "out", "", "同 -o")
	fs.StringVar(&plan, "p", "plan-m7-mw", "采集计划 ID")
	fs.StringVar(&plan, "plan", "plan-m7-mw", "同 -p")
	fs.StringVar(&hospital, "H", "", "医院 ID（缺省环境 MEDAUDIT_HOSPITAL）")
	fs.StringVar(&hospital, "hospital", "", "同 -H")
	fs.StringVar(&asset, "asset", "", "资产 ID（或第三个位置参数）")
	pos, err := splitPos(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 && typ == "" {
		typ = pos[0]
		pos = pos[1:]
	}
	if len(pos) > 0 && home == "" {
		home = pos[0]
		pos = pos[1:]
	}
	if len(pos) > 0 && asset == "" {
		asset = pos[0]
	}
	if typ == "" {
		return fmt.Errorf("用法：mw <tomcat|nginx|weblogic|iis> [目录] [资产id] [-o 输出.zip]")
	}
	if typ != "iis" && home == "" {
		return fmt.Errorf("目录必填（iis 除外）：mw %s <目录>", typ)
	}
	if out == "" {
		out = autoBundleName("mw-" + typ)
	}
	hospital = resolveHospital(hospital, "h-m1-test")
	opts := mw.Options{Home: home, HospitalID: hospital, AssetID: asset, PlanID: plan}
	var b *facts.FactBundle
	switch typ {
	case "tomcat":
		if opts.AssetID == "" {
			opts.AssetID = "mw-tomcat-local"
		}
		b, err = mw.CollectTomcat(opts)
	case "nginx":
		if opts.AssetID == "" {
			opts.AssetID = "mw-nginx-local"
		}
		b, err = mw.CollectNginx(opts)
	case "weblogic":
		if opts.AssetID == "" {
			opts.AssetID = "mw-weblogic-local"
		}
		b, err = mw.CollectWebLogic(opts)
	case "iis":
		if opts.AssetID == "" {
			opts.AssetID = "mw-iis-local"
		}
		b, err = mw.CollectIIS(opts)
	default:
		return fmt.Errorf("不支持的中间件 type: %s（tomcat|nginx|weblogic|iis）", typ)
	}
	if err != nil {
		return fmt.Errorf("采集失败: %w", err)
	}
	if errs := b.Validate(); len(errs) != 0 {
		return fmt.Errorf("事实包校验失败: %v", errs)
	}
	if err := facts.WriteZip(out, b); err != nil {
		return err
	}
	fmt.Printf("MW 采集完成 [%s]：%d facts, %d receipts, %s → %s\n",
		typ, len(b.Facts), len(b.Receipts), b.Execution, out)
	return nil
}

func loadDBConfig(path string) (*DBFileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg DBFileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析 YAML 失败: %w", err)
	}
	if cfg.Host == "" || cfg.User == "" {
		return nil, fmt.Errorf("config 缺少 host/user")
	}
	return &cfg, nil
}

func parseDur(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}

// ---------- bundle ----------

func runBundle(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("用法：bundle <verify|upload> ...")
	}
	switch args[0] {
	case "verify":
		return bundleVerify(args[1:])
	case "upload":
		return bundleUpload(args[1:])
	default:
		return fmt.Errorf("未知 bundle 子命令: %s", args[0])
	}
}

func bundleVerify(args []string) error {
	fs := flag.NewFlagSet("bundle verify", flag.ContinueOnError)
	var file string
	fs.StringVar(&file, "file", "", "事实包路径（或第一个位置参数）")
	pos, err := splitPos(fs, args)
	if err != nil {
		return err
	}
	if file == "" && len(pos) > 0 {
		file = pos[0]
	}
	if file == "" {
		return fmt.Errorf("用法：bundle verify <文件.zip>")
	}
	b, err := facts.ReadZip(file)
	if err != nil {
		return err
	}
	if errs := b.Validate(); len(errs) != 0 {
		return fmt.Errorf("校验失败: %v", errs)
	}
	fmt.Printf("校验通过：%s | adapter=%s | facts=%d receipts=%d execution=%s\n",
		b.BundleID, b.Collector.Adapter, len(b.Facts), len(b.Receipts), b.Execution)
	return nil
}

func bundleUpload(args []string) error {
	fs := flag.NewFlagSet("bundle upload", flag.ContinueOnError)
	var file, server string
	fs.StringVar(&file, "file", "", "事实包路径（或第一个位置参数）")
	fs.StringVar(&server, "server", "", "管理服务地址（或第二个位置参数；缺省环境 MEDAUDIT_SERVER）")
	pos, err := splitPos(fs, args)
	if err != nil {
		return err
	}
	if file == "" && len(pos) > 0 {
		file = pos[0]
	}
	if server == "" && len(pos) > 1 {
		server = pos[1]
	}
	if server == "" {
		server = os.Getenv("MEDAUDIT_SERVER")
	}
	if file == "" || server == "" {
		return fmt.Errorf("用法：bundle upload <文件.zip> [服务地址]")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	url := strings.TrimSuffix(server, "/") + "/api/v1/bundles"
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/zip")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("上传失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("服务端拒绝（%d）: %s", resp.StatusCode, string(body))
	}
	fmt.Printf("上传成功（%d）: %s\n", resp.StatusCode, string(body))
	return nil
}

// errPreflightPartial 预检结论为「可采集但不完整」：main 以退出码 3 结束（不打印错误行）。
var errPreflightPartial = errors.New("preflight: partial")

// printPreflight 打印采集可达性预检：逐模板收据 + 完整性结论。不生成事实包。
// 采集走与正式采集完全相同的 Collect 路径，结论即正式采集的预期结果。
func printPreflight(b *facts.FactBundle, cfg *DBFileConfig) error {
	fmt.Printf("预检：%s %s@%s:%d，目标版本 %s\n", b.Collector.Adapter, cfg.User, cfg.Host, cfg.Port, b.Scope.TargetVersion)
	fmt.Printf("%-30s %-18s %8s %6s %9s\n", "模板", "状态", "行数", "截断", "耗时ms")
	var gaps []string
	for _, r := range b.Receipts {
		truncMark, truncNote := "", ""
		if r.Truncated {
			truncMark, truncNote = "是", "，已截断"
		}
		fmt.Printf("%-30s %-18s %8d %6s %9d\n", r.TemplateID, r.Status, r.RowCount, truncMark, r.DurationMs)
		if r.Status != "ok" || r.Truncated {
			gaps = append(gaps, fmt.Sprintf("%s（%s%s）", r.TemplateID, r.Status, truncNote))
		}
	}
	fmt.Printf("执行状态 %s：事实 %d / 收据 %d\n", b.Execution, len(b.Facts), len(b.Receipts))
	if b.Execution == facts.ExecutionComplete && len(gaps) == 0 {
		fmt.Println("预检结论：连接与权限满足完整采集，可正式采集。")
		return nil
	}
	fmt.Printf("预检结论：可连接，但采集不完整（%s）——以下模板存在缺口：\n", b.Execution)
	for _, g := range gaps {
		fmt.Println("  - " + g)
	}
	return errPreflightPartial
}
