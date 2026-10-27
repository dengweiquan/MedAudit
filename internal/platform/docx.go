package platform

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"medaudit/internal/rules"
)

// GetReportSnapshot 读取报告快照 JSON 原文。
func GetReportSnapshot(db *sql.DB, reportID string) (string, error) {
	var snap string
	err := db.QueryRow(`SELECT snapshot FROM reports WHERE id = ?`, reportID).Scan(&snap)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("报告 %s 不存在", reportID)
	}
	return snap, err
}

// ---- OOXML(docx) 生成：样式 v2（M18 报告专业化排版） ----
// 版式：封面信息区 / 章节标题带下划线 / 表头深蓝底白字 / 标签表浅蓝左列 /
// 代码块等宽浅灰底 / 页眉（平台名+内部敏感）/ 页脚（报告编号+页码）。

func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}

type runStyle struct {
	Bold  bool
	Ital  bool
	Color string // RRGGBB，不带 #
	Sz    int    // 半磅，0=默认
	Mono  bool
}

func runXML(text string, o runStyle) string {
	var pr strings.Builder
	pr.WriteString("<w:rPr>")
	if o.Mono {
		pr.WriteString(`<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="Microsoft YaHei"/>`)
	}
	if o.Bold {
		pr.WriteString("<w:b/>")
	}
	if o.Ital {
		pr.WriteString("<w:i/>")
	}
	if o.Color != "" {
		pr.WriteString(`<w:color w:val="` + o.Color + `"/>`)
	}
	if o.Sz > 0 {
		pr.WriteString(fmt.Sprintf(`<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, o.Sz, o.Sz))
	}
	pr.WriteString("</w:rPr>")
	// 多行文本以 <w:br/> 分隔，保证 xml:space 保留行内空格。
	lines := strings.Split(text, "\n")
	var sb strings.Builder
	for i, ln := range lines {
		if i > 0 {
			sb.WriteString("<w:r>" + pr.String() + "<w:br/></w:r>")
		}
		sb.WriteString("<w:r>" + pr.String() + `<w:t xml:space="preserve">` + xmlEsc(ln) + "</w:t></w:r>")
	}
	return sb.String()
}

func paraRuns(runs string, style, align string) string {
	var sb strings.Builder
	sb.WriteString("<w:p><w:pPr>")
	if style != "" {
		sb.WriteString(`<w:pStyle w:val="` + style + `"/>`)
	}
	if align != "" {
		sb.WriteString(`<w:jc w:val="` + align + `"/>`)
	}
	sb.WriteString("</w:pPr>")
	sb.WriteString(runs)
	sb.WriteString("</w:p>")
	return sb.String()
}

func docxPara(text, style string) string {
	return paraRuns(runXML(text, runStyle{}), style, "")
}

func grayPara(text string) string { return docxPara(text, "CaptionGray") }

// leadPara 以加粗引导词开头的正文段（如「整改建议：……」）。
func leadPara(lead, text string) string {
	return paraRuns(runXML(lead, runStyle{Bold: true})+runXML(text, runStyle{}), "", "")
}

// codePara 代码块段落：等宽+浅灰底。底纹用直接格式（样式内 shd 在部分
// 渲染器不生效），CodeBlock 样式仅作语义标注。
func codePara(text string) string {
	return `<w:p><w:pPr><w:pStyle w:val="CodeBlock"/><w:shd w:val="clear" w:fill="F2F4F7"/><w:spacing w:before="60" w:after="160"/><w:ind w:left="140" w:right="140"/></w:pPr>` +
		runXML(text, runStyle{Mono: true}) + `</w:p>`
}

type tableOpts struct {
	Widths     []int // dxa，总宽约 9500；nil=等分
	Header     bool  // 首行表头（深蓝底白字加粗）
	LabelFirst bool  // 首列标签（浅蓝底加粗）
	FontSz     int   // 单元格字号（半磅），0=默认
	MonoCols   map[int]bool
}

func docxTableEx(rows [][]string, o tableOpts) string {
	if len(rows) == 0 {
		return ""
	}
	cols := 0
	for _, r := range rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	widths := o.Widths
	if len(widths) != cols {
		widths = make([]int, cols)
		for i := range widths {
			widths[i] = 9500 / cols
		}
	}
	var sb strings.Builder
	sb.WriteString(`<w:tbl><w:tblPr><w:tblStyle w:val="ReportTable"/><w:tblW w:w="9500" w:type="dxa"/><w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>`)
	for _, w := range widths {
		sb.WriteString(fmt.Sprintf(`<w:gridCol w:w="%d"/>`, w))
	}
	sb.WriteString("</w:tblGrid>")
	for ri, row := range rows {
		sb.WriteString("<w:tr>")
		// cantSplit：行不跨页断裂，避免页首出现残行。
		if o.Header && ri == 0 {
			sb.WriteString(`<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>`)
		} else {
			sb.WriteString(`<w:trPr><w:cantSplit/></w:trPr>`)
		}
		for ci, cell := range row {
			isHeader := o.Header && ri == 0
			isLabel := o.LabelFirst && ci == 0
			sb.WriteString("<w:tc><w:tcPr>")
			sb.WriteString(fmt.Sprintf(`<w:tcW w:w="%d" w:type="dxa"/>`, widths[ci]))
			if isHeader {
				sb.WriteString(`<w:shd w:val="clear" w:fill="2F5596"/>`)
			} else if isLabel {
				sb.WriteString(`<w:shd w:val="clear" w:fill="D9E2F3"/>`)
			}
			sb.WriteString("</w:tcPr>")
			rs := runStyle{Sz: o.FontSz, Mono: o.MonoCols[ci]}
			if isHeader {
				rs.Bold = true
				rs.Color = "FFFFFF"
			}
			if isLabel {
				rs.Bold = true
				rs.Color = "1F3864"
			}
			sb.WriteString(paraRuns(runXML(cell, rs), "", ""))
			sb.WriteString("</w:tc>")
		}
		sb.WriteString("</w:tr>")
	}
	sb.WriteString("</w:tbl>")
	// 表格后留一个空段，避免相邻表格/标题粘连。
	sb.WriteString(docxPara("", ""))
	return sb.String()
}

// docxTable 兼容入口（API 报告 / 离线评估报告共用）：带边框表格，首行不特殊着色。
func docxTable(rows [][]string) string {
	return docxTableEx(rows, tableOpts{})
}

const docxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>`

const docxRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`

const docxDocRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>`

const docxStyles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Microsoft YaHei"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-US" w:eastAsia="zh-CN"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="300" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:color w:val="262626"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="56"/><w:szCs w:val="56"/><w:color w:val="1F3864"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="ReportOverline"><w:name w:val="报告眉题"/><w:pPr><w:spacing w:after="60"/></w:pPr><w:rPr><w:b/><w:sz w:val="20"/><w:szCs w:val="20"/><w:color w:val="2F5596"/><w:spacing w:val="30"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="ReportSubtitle"><w:name w:val="报告副题"/><w:pPr><w:spacing w:after="360"/></w:pPr><w:rPr><w:sz w:val="26"/><w:szCs w:val="26"/><w:color w:val="595959"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:keepNext/><w:spacing w:before="400" w:after="180"/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="4" w:color="2F5596"/></w:pBdr></w:pPr><w:rPr><w:b/><w:sz w:val="32"/><w:szCs w:val="32"/><w:color w:val="1F4E79"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:pPr><w:keepNext/><w:spacing w:before="320" w:after="140"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/><w:szCs w:val="26"/><w:color w:val="2F5596"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="100"/></w:pPr><w:rPr><w:b/><w:sz w:val="23"/><w:szCs w:val="23"/><w:color w:val="404040"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="CaptionGray"><w:name w:val="小字说明"/><w:pPr><w:spacing w:after="100"/></w:pPr><w:rPr><w:sz w:val="18"/><w:szCs w:val="18"/><w:color w:val="808080"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="CodeBlock"><w:name w:val="代码块"/><w:pPr><w:shd w:val="clear" w:fill="F2F4F7"/><w:spacing w:before="60" w:after="160"/><w:ind w:left="140" w:right="140"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="19"/><w:szCs w:val="19"/><w:color w:val="1F1F1F"/></w:rPr></w:style><w:style w:type="table" w:styleId="ReportTable"><w:name w:val="Report Table"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="B4C6E7"/><w:left w:val="single" w:sz="4" w:space="0" w:color="B4C6E7"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="B4C6E7"/><w:right w:val="single" w:sz="4" w:space="0" w:color="B4C6E7"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="B4C6E7"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="B4C6E7"/></w:tblBorders><w:tblCellMar><w:top w:w="50" w:type="dxa"/><w:bottom w:w="50" w:type="dxa"/><w:left w:w="110" w:type="dxa"/><w:right w:w="110" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style></w:styles>`

func docxHeaderXML(right string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:tabs><w:tab w:val="right" w:pos="9500"/></w:tabs><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="6" w:color="BFBFBF"/></w:pBdr><w:spacing w:after="40"/></w:pPr>` +
		runXML("MedAudit 医疗权限核查平台", runStyle{Sz: 18, Color: "808080"}) +
		`<w:r><w:tab/></w:r>` +
		runXML(right, runStyle{Sz: 18, Color: "808080"}) +
		`</w:p></w:hdr>`
}

func pageField(code string) string {
	return `<w:r><w:rPr><w:sz w:val="18"/><w:color w:val="808080"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r>` +
		`<w:r><w:rPr><w:sz w:val="18"/><w:color w:val="808080"/></w:rPr><w:instrText xml:space="preserve"> ` + code + ` </w:instrText></w:r>` +
		`<w:r><w:rPr><w:sz w:val="18"/><w:color w:val="808080"/></w:rPr><w:fldChar w:fldCharType="separate"/></w:r>` +
		`<w:r><w:rPr><w:sz w:val="18"/><w:color w:val="808080"/></w:rPr><w:t>1</w:t></w:r>` +
		`<w:r><w:rPr><w:sz w:val="18"/><w:color w:val="808080"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r>`
}

func docxFooterXML(left string) string {
	if left == "" {
		left = "MedAudit 平台自动生成"
	}
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:tabs><w:tab w:val="right" w:pos="9500"/></w:tabs><w:pBdr><w:top w:val="single" w:sz="4" w:space="6" w:color="BFBFBF"/></w:pBdr><w:spacing w:before="40"/></w:pPr>` +
		runXML(left, runStyle{Sz: 18, Color: "808080"}) +
		`<w:r><w:tab/></w:r>` +
		runXML("第 ", runStyle{Sz: 18, Color: "808080"}) + pageField("PAGE") +
		runXML(" 页 / 共 ", runStyle{Sz: 18, Color: "808080"}) + pageField("NUMPAGES") +
		runXML(" 页", runStyle{Sz: 18, Color: "808080"}) +
		`</w:p></w:ftr>`
}

// assembleDocx 组装完整 .docx（含页眉页脚与页码）。
func assembleDocx(bodyXML, headerRight, footerLeft string) ([]byte, error) {
	doc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>` +
		bodyXML +
		`<w:sectPr><w:headerReference w:type="default" r:id="rId2"/><w:footerReference w:type="default" r:id="rId3"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1361" w:right="1190" w:bottom="1361" w:left="1190" w:header="720" w:footer="720"/></w:sectPr></w:body></w:document>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"[Content_Types].xml":          docxContentTypes,
		"_rels/.rels":                  docxRels,
		"word/document.xml":            doc,
		"word/styles.xml":              docxStyles,
		"word/header1.xml":             docxHeaderXML(headerRight),
		"word/footer1.xml":             docxFooterXML(footerLeft),
		"word/_rels/document.xml.rels": docxDocRels,
	} {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// packDocx 把正文 XML 片段组装为完整 .docx（API 报告/离线评估报告共用默认页眉页脚）。
func packDocx(bodyXML string) ([]byte, error) {
	return assembleDocx(bodyXML, "内部敏感", "")
}

// ---- 报告渲染（M18 专业版式） ----

type snapFinding struct {
	RuleID     string `json:"rule_id"`
	Subject    string `json:"subject"`
	Conclusion string `json:"conclusion"`
	Detail     string `json:"detail"`
}

type findingDetail struct {
	Risk     string   `json:"risk"`
	Detail   string   `json:"detail"`
	Missing  string   `json:"missing"`
	Evidence []string `json:"evidence"`
}

type reportMeta struct {
	HospitalName     string `json:"hospital_name"`
	AssetID          string `json:"asset_id"`
	AssetName        string `json:"asset_name"`
	AssetKind        string `json:"asset_kind"`
	BundleImportedAt string `json:"bundle_imported_at"`
}

type reportSnapshot struct {
	HospitalID        string                    `json:"hospital_id"`
	BundleID          string                    `json:"bundle_id"`
	Adapter           string                    `json:"adapter"`
	Execution         string                    `json:"execution"`
	GeneratedAt       string                    `json:"generated_at"`
	ConclusionSummary map[string]int            `json:"conclusion_summary"`
	Coverage          map[string]map[string]any `json:"coverage"`
	CoverageNote      string                    `json:"coverage_note"`
	Findings          []snapFinding             `json:"findings"`
	ReportMeta        *reportMeta               `json:"report_meta"`
	PrivilegePaths    map[string]any            `json:"privilege_paths"`
	Drift             map[string]any            `json:"drift"`
	Remediation       map[string]any            `json:"remediation"`
}

// 显示时区见 display_time.go（displayZone，默认 Asia/Shanghai）

// fmtTimeCN 把 RFC3339(UTC) 转北京时间可读格式；解析失败原样返回。
func fmtTimeCN(s string) string {
	if s == "" {
		return "—"
	}
	if t, ok := parseStoredTime(s); ok {
		return t.In(displayZone).Format("2006年1月2日 15:04")
	}
	return s
}

func numStr(v any) string {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return fmt.Sprintf("%d", int64(n))
		}
		return fmt.Sprintf("%v", n)
	case string:
		return n
	case nil:
		return "—"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func mapCount(sec map[string]any, key string) (map[string]any, bool) {
	m, ok := sec[key].(map[string]any)
	return m, ok
}

func riskCN(r string) string {
	switch strings.ToLower(r) {
	case "high", "critical":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	}
	return r
}

func riskWeight(r string) int {
	switch strings.ToLower(r) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func conclCN(c string) string {
	switch c {
	case "FAIL":
		return "不通过（FAIL）"
	case "PASS":
		return "通过（PASS）"
	case "UNKNOWN":
		return "未知（UNKNOWN）"
	case "NOT_RUN":
		return "未执行（NOT_RUN）"
	case "NOT_APPLICABLE":
		return "不适用（NOT_APPLICABLE）"
	}
	return c
}

func execCN(e string) string {
	switch e {
	case "COMPLETE":
		return "完整（COMPLETE）"
	case "PARTIAL":
		return "部分完成（PARTIAL）"
	case "FAILED":
		return "执行失败（FAILED）"
	}
	return e
}

func adapterCN(a string) string {
	switch a {
	case "db-mysql":
		return "MySQL"
	case "db-postgres":
		return "PostgreSQL"
	case "db-mssql":
		return "SQL Server"
	case "db-oracle":
		return "Oracle"
	case "os-linux":
		return "Linux"
	case "os-windows":
		return "Windows"
	case "mw-tomcat":
		return "Tomcat"
	case "mw-nginx":
		return "Nginx"
	case "mw-weblogic":
		return "WebLogic"
	case "mw-iis":
		return "IIS"
	}
	return a
}

func kindCN(kind string) string {
	switch {
	case strings.HasPrefix(kind, "db-"):
		return "数据库"
	case strings.HasPrefix(kind, "os-"), kind == "host":
		return "操作系统"
	case strings.HasPrefix(kind, "mw-"):
		return "中间件"
	case kind == "api":
		return "业务接口"
	}
	return kind
}

var ruleSpecCache map[string]rules.RuleSpec

func ruleSpecOf(id string) (rules.RuleSpec, bool) {
	if ruleSpecCache == nil {
		ruleSpecCache = map[string]rules.RuleSpec{}
		for _, s := range rules.DefaultRegistry().Rules() {
			ruleSpecCache[s.ID] = s
		}
	}
	s, ok := ruleSpecCache[id]
	return s, ok
}

func ruleName(id string) string {
	if s, ok := ruleSpecOf(id); ok && s.Name != "" {
		return s.Name
	}
	return id
}

// RenderReportDocx 把报告快照 JSON 渲染为专业排版的 .docx。
// reportID 用于封面与页脚（旧调用可传空）。渲染只读快照+规则注册表，
// 与生成时点口径无关；快照缺失的展示字段自动降级为 ID。
func RenderReportDocx(snapshotJSON string, reportID string) ([]byte, error) {
	var snap reportSnapshot
	if err := json.Unmarshal([]byte(snapshotJSON), &snap); err != nil {
		return nil, fmt.Errorf("快照解析失败: %w", err)
	}
	meta := snap.ReportMeta
	if meta == nil {
		meta = &reportMeta{}
	}
	assetSec := snap.Coverage["asset"]
	targetType := snap.Adapter
	targetVersion := ""
	if assetSec != nil {
		if v, ok := assetSec["target_type"].(string); ok && v != "" {
			targetType = v
		}
		targetVersion, _ = assetSec["target_version"].(string)
		if meta.AssetID == "" {
			meta.AssetID, _ = assetSec["asset_id"].(string)
		}
	}
	// 历史自动登记的医院/对象名带 "auto-created:" 前缀，展示时去掉。
	stripAuto := func(s string) string { return strings.TrimPrefix(s, "auto-created:") }
	assetName := stripAuto(meta.AssetName)
	if assetName == "" {
		assetName = stripAuto(meta.AssetID)
	}
	hospitalName := stripAuto(meta.HospitalName)
	if hospitalName == "" {
		hospitalName = stripAuto(snap.HospitalID)
	}
	category := kindCN(meta.AssetKind)
	if category == "" || category == meta.AssetKind {
		category = kindCN(targetType)
	}

	// 解析 findings 明细与分组。
	type fItem struct {
		f    snapFinding
		d    findingDetail
		risk string
	}
	items := make([]fItem, 0, len(snap.Findings))
	failByRisk := map[string]int{}
	var failN, unknownN, notRunN int
	for _, f := range snap.Findings {
		var d findingDetail
		_ = json.Unmarshal([]byte(f.Detail), &d)
		risk := d.Risk
		if risk == "" {
			if s, ok := ruleSpecOf(f.RuleID); ok {
				risk = string(s.Risk)
			}
		}
		items = append(items, fItem{f, d, risk})
		switch f.Conclusion {
		case "FAIL":
			failN++
			failByRisk[strings.ToLower(risk)]++
		case "UNKNOWN":
			unknownN++
		case "NOT_RUN":
			notRunN++
		}
	}
	// 技术口径重算的完整结论分布（可判定章节）。
	detSec := snap.Coverage["determinability"]
	byConcl, _ := mapCount(detSec, "by_conclusion")
	passN := 0
	if byConcl != nil {
		if v, ok := byConcl["PASS"].(float64); ok {
			passN = int(v)
		}
	}

	var body strings.Builder
	secNo := 0
	secTitle := func(t string) string {
		secNo++
		return docxPara(fmt.Sprintf("%s、%s", []string{"一", "二", "三", "四", "五", "六", "七", "八"}[secNo-1], t), "Heading1")
	}

	// ---------- 封面区 ----------
	body.WriteString(docxPara("MEDAUDIT 医疗权限核查平台", "ReportOverline"))
	body.WriteString(docxPara("权限审计报告", "Title"))
	subtitle := assetName
	if category != "" {
		subtitle += " · " + category
	}
	if e := adapterCN(targetType); e != targetType {
		subtitle += "（" + e + "）"
	}
	body.WriteString(docxPara(subtitle, "ReportSubtitle"))
	infoRows := [][]string{
		{"医院", hospitalName},
		{"审计对象", assetName},
		{"对象类型", strings.Trim(category+" · "+adapterCN(targetType), " ·")},
	}
	if targetVersion != "" {
		infoRows = append(infoRows, []string{"目标版本", targetVersion})
	}
	if meta.BundleImportedAt != "" {
		infoRows = append(infoRows, []string{"审计时间", DisplayTime(meta.BundleImportedAt)})
	}
	infoRows = append(infoRows,
		[]string{"事实包编号", snap.BundleID},
		[]string{"报告生成时间", fmtTimeCN(snap.GeneratedAt)},
	)
	if reportID != "" {
		infoRows = append(infoRows, []string{"报告编号", reportID})
	}
	infoRows = append(infoRows,
		[]string{"执行状态", execCN(snap.Execution)},
		[]string{"评估口径", "问题清单为平台落库结论；通过数与可判定率由生成报告时以技术口径对同一事实包重评估得到"},
	)
	body.WriteString(docxTableEx(infoRows, tableOpts{Widths: []int{1800, 7700}, LabelFirst: true}))
	body.WriteString(paraRuns(runXML("本报告包含目标系统的权限配置明细，请按内部敏感文档管理，不得外传。", runStyle{Ital: true, Color: "808080", Sz: 19}), "", ""))

	// ---------- 执行摘要 ----------
	body.WriteString(secTitle("执行摘要"))
	totalChecks := numStr(detSec["rule_results_total"])
	summaryText := fmt.Sprintf("本次审计对象为 %s（%s），共执行检查 %s 项。", assetName, adapterCN(targetType), totalChecks)
	if failN > 0 {
		summaryText += fmt.Sprintf("发现待整改问题 %d 项，其中高风险 %d 项、中风险 %d 项、低风险 %d 项，明细见问题章节，请按规则逐项整改并重新审计确认消除。",
			failN, failByRisk["high"]+failByRisk["critical"], failByRisk["medium"], failByRisk["low"])
	} else {
		summaryText += "未发现待整改问题（FAIL）。"
	}
	if unknownN > 0 {
		summaryText += fmt.Sprintf("另有 %d 项因证据不足结论为未知（UNKNOWN），需人工确认。", unknownN)
	}
	if notRunN > 0 {
		summaryText += fmt.Sprintf("另有 %d 项未执行（NOT_RUN）。", notRunN)
	}
	if snap.Execution == "PARTIAL" {
		summaryText += "注意：本次采集执行状态为部分完成（PARTIAL），覆盖不完整，结论可能不完整，请结合「审计说明」的覆盖情况判断。"
	}
	body.WriteString(docxPara(summaryText, ""))

	conclRows := [][]string{{"结论", "数量", "说明"}}
	conclDesc := map[string]string{
		"FAIL":           "发现不符合安全要求的问题，需整改",
		"PASS":           "检查通过（技术口径重评估）",
		"UNKNOWN":        "证据不足，需人工确认",
		"NOT_RUN":        "本次未执行",
		"NOT_APPLICABLE": "对该对象不适用",
	}
	conclCounts := map[string]int{"FAIL": failN, "UNKNOWN": unknownN, "NOT_RUN": notRunN, "PASS": passN}
	if byConcl != nil {
		if v, ok := byConcl["NOT_APPLICABLE"].(float64); ok {
			conclCounts["NOT_APPLICABLE"] = int(v)
		}
	}
	for _, c := range []string{"FAIL", "PASS", "UNKNOWN", "NOT_RUN", "NOT_APPLICABLE"} {
		// FAIL/PASS 恒列示；其余结论为 0 时不列，避免空行噪音。
		if n, ok := conclCounts[c]; ok && (n > 0 || c == "FAIL" || c == "PASS") {
			conclRows = append(conclRows, []string{conclCN(c), fmt.Sprintf("%d", n), conclDesc[c]})
		}
	}
	body.WriteString(docxTableEx(conclRows, tableOpts{Widths: []int{2200, 1000, 6300}, Header: true}))

	// 问题分布（按规则汇总，仅 FAIL）。
	if failN > 0 {
		type agg struct {
			ruleID   string
			risk     string
			count    int
			subjects map[string]bool
		}
		aggs := map[string]*agg{}
		for _, it := range items {
			if it.f.Conclusion != "FAIL" {
				continue
			}
			a := aggs[it.f.RuleID]
			if a == nil {
				a = &agg{ruleID: it.f.RuleID, risk: it.risk, subjects: map[string]bool{}}
				aggs[it.f.RuleID] = a
			}
			a.count++
			a.subjects[it.f.Subject] = true
			if riskWeight(it.risk) > riskWeight(a.risk) {
				a.risk = it.risk
			}
		}
		list := make([]*agg, 0, len(aggs))
		for _, a := range aggs {
			list = append(list, a)
		}
		sort.Slice(list, func(i, j int) bool {
			if riskWeight(list[i].risk) != riskWeight(list[j].risk) {
				return riskWeight(list[i].risk) > riskWeight(list[j].risk)
			}
			if list[i].count != list[j].count {
				return list[i].count > list[j].count
			}
			return list[i].ruleID < list[j].ruleID
		})
		rows := [][]string{{"问题类别（规则）", "风险", "问题数", "涉及主体数"}}
		for _, a := range list {
			rows = append(rows, []string{
				ruleName(a.ruleID) + "（" + a.ruleID + "）",
				riskCN(a.risk), fmt.Sprintf("%d", a.count), fmt.Sprintf("%d", len(a.subjects)),
			})
		}
		body.WriteString(docxPara("问题分布（按规则汇总）", "Heading2"))
		body.WriteString(docxTableEx(rows, tableOpts{Widths: []int{4900, 900, 1100, 1300}, Header: true}))

		// 等保条款对照：把不通过的问题按条款归集，便于对照测评要求整改。
		type ctlAgg struct {
			c     rules.Control
			count int
			rules []string
		}
		byCtl := map[string]*ctlAgg{}
		for _, a := range list {
			for _, c := range rules.ControlsFor(a.ruleID) {
				ca := byCtl[c.ID]
				if ca == nil {
					ca = &ctlAgg{c: c}
					byCtl[c.ID] = ca
				}
				ca.count += a.count
				ca.rules = append(ca.rules, ruleName(a.ruleID))
			}
		}
		if len(byCtl) > 0 {
			ctls := make([]*ctlAgg, 0, len(byCtl))
			for _, ca := range byCtl {
				ctls = append(ctls, ca)
			}
			sort.Slice(ctls, func(i, j int) bool { return ctls[i].c.ID < ctls[j].c.ID })
			crow := [][]string{{"条款", "要求要点", "问题数", "涉及问题类别"}}
			for _, ca := range ctls {
				crow = append(crow, []string{
					ca.c.ID + " " + ca.c.Group, ca.c.Title,
					fmt.Sprintf("%d", ca.count), strings.Join(ca.rules, "；"),
				})
			}
			body.WriteString(docxPara("等保条款对照", "Heading2"))
			body.WriteString(grayPara("依据：" + rules.ComplianceFramework + "。条款要求为要点概述，正式引用以标准原文为准；一个问题可能对应多个条款。"))
			body.WriteString(docxTableEx(crow, tableOpts{Widths: []int{1700, 3300, 900, 3300}, Header: true, FontSz: 19}))
		}
	}

	// ---------- 审计说明 ----------
	body.WriteString(secTitle("审计说明"))
	if errMsg, ok := snap.Coverage["error"]; ok {
		body.WriteString(docxPara("覆盖计算异常："+numStr(errMsg), ""))
	}
	covRows := [][]string{}
	addCov := func(label string, sec map[string]any, key string) {
		if sec != nil {
			if v, ok := sec[key]; ok {
				covRows = append(covRows, []string{label, numStr(v)})
			}
		}
	}
	evSec := snap.Coverage["evidence"]
	accSec := snap.Coverage["accounts"]
	linkSec := snap.Coverage["linkage"]
	addCov("采集事实总数", evSec, "facts_total")
	addCov("被核查账号数（去重）", accSec, "distinct_identity_subjects")
	addCov("权限事实数", accSec, "privilege_facts")
	addCov("角色关系数", accSec, "role_edges")
	addCov("服务配置事实数", linkSec, "service_config_facts")
	addCov("进程事实数", linkSec, "process_facts")
	addCov("数据库事实数", linkSec, "database_facts")
	addCov("采集收据总数", evSec, "receipts_total")
	addCov("被拒绝的采集项", evSec, "receipts_denied")
	addCov("权限不足的事实数", evSec, "permission_denied_facts")
	if byKind, ok := mapCount(evSec, "by_kind"); ok {
		keys := make([]string, 0, len(byKind))
		for k := range byKind {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %s", kindFactCN(k), numStr(byKind[k])))
		}
		covRows = append(covRows, []string{"事实构成", strings.Join(parts, "；")})
	}
	if len(covRows) > 0 {
		body.WriteString(docxPara("采集覆盖", "Heading2"))
		body.WriteString(docxTableEx(covRows, tableOpts{Widths: []int{2600, 6900}, LabelFirst: true}))
	}
	if detSec != nil {
		rows := [][]string{}
		rows = append(rows, []string{"检查项总数", numStr(detSec["rule_results_total"])})
		rows = append(rows, []string{"适用检查项", numStr(detSec["applicable"])})
		rows = append(rows, []string{"可判定检查项", numStr(detSec["determinable"])})
		if rv, ok := detSec["determinable_rate"].(float64); ok {
			rows = append(rows, []string{"可判定率", fmt.Sprintf("%.0f%%", rv*100)})
		}
		body.WriteString(docxPara("可判定性（技术口径重评估）", "Heading2"))
		body.WriteString(docxTableEx(rows, tableOpts{Widths: []int{2600, 6900}, LabelFirst: true}))
	}
	body.WriteString(leadPara("口径说明：", "问题清单与问题分布以平台落库结论为准（生成报告时点的评估结果，含当时启用的基线与规则启停状态）；通过数与可判定率由生成报告时以技术口径（无基线）对同一事实包重评估得到，两者口径不同属正常现象。可判定率 =（通过 + 不通过）/ 适用检查项。"))

	// ---------- 问题明细 ----------
	body.WriteString(secTitle("问题明细"))
	if len(items) == 0 {
		body.WriteString(docxPara("本次审计问题清单为空，未发现问题。", ""))
	} else {
		groups := map[string][]fItem{}
		var order []string
		for _, it := range items {
			if _, ok := groups[it.f.RuleID]; !ok {
				order = append(order, it.f.RuleID)
			}
			groups[it.f.RuleID] = append(groups[it.f.RuleID], it)
		}
		groupRisk := func(id string) string {
			best := ""
			for _, it := range groups[id] {
				if riskWeight(it.risk) > riskWeight(best) {
					best = it.risk
				}
			}
			return best
		}
		sort.Slice(order, func(i, j int) bool {
			wi, wj := riskWeight(groupRisk(order[i])), riskWeight(groupRisk(order[j]))
			if wi != wj {
				return wi > wj
			}
			if len(groups[order[i]]) != len(groups[order[j]]) {
				return len(groups[order[i]]) > len(groups[order[j]])
			}
			return order[i] < order[j]
		})
		for _, rid := range order {
			g := groups[rid]
			spec, hasSpec := ruleSpecOf(rid)
			body.WriteString(docxPara(ruleName(rid)+"（"+rid+"）", "Heading2"))
			subjSet := map[string]bool{}
			conclSet := map[string]bool{}
			for _, it := range g {
				subjSet[it.f.Subject] = true
				conclSet[it.f.Conclusion] = true
			}
			var conclNames []string
			for c := range conclSet {
				conclNames = append(conclNames, conclCN(c))
			}
			sort.Strings(conclNames)
			body.WriteString(grayPara(fmt.Sprintf("风险等级：%s · 结论：%s · 问题数：%d · 涉及主体：%d",
				riskCN(groupRisk(rid)), strings.Join(conclNames, "、"), len(g), len(subjSet))))
			if hasSpec && spec.Description != "" {
				body.WriteString(docxPara(spec.Description, ""))
			}
			if hasSpec && spec.Remediation != "" {
				body.WriteString(leadPara("整改建议：", spec.Remediation))
			}
			if cs := rules.ControlsFor(rid); len(cs) > 0 {
				refs := make([]string, len(cs))
				for i, c := range cs {
					refs[i] = c.ID + " " + c.Group
				}
				body.WriteString(grayPara("对应等保条款：" + strings.Join(refs, "；")))
			}
			rows := [][]string{{"序号", "主体", "结论", "问题说明", "证据"}}
			for i, it := range g {
				desc := it.d.Detail
				if desc == "" {
					desc = "—"
				}
				if it.d.Missing != "" {
					desc += "（证据缺失：" + it.d.Missing + "）"
				}
				ev := "—"
				if len(it.d.Evidence) > 0 {
					ev = strings.Join(it.d.Evidence, ", ")
				}
				rows = append(rows, []string{
					fmt.Sprintf("%d", i+1), it.f.Subject, conclCN(it.f.Conclusion), desc, ev,
				})
			}
			body.WriteString(docxTableEx(rows, tableOpts{
				Widths: []int{600, 1700, 1300, 3800, 2100}, Header: true, FontSz: 19,
			}))
		}
	}

	// ---------- 跨层提权路径 ----------
	if sec := snap.PrivilegePaths; sec != nil {
		body.WriteString(secTitle("跨层提权路径（关联分析）"))
		body.WriteString(docxPara(fmt.Sprintf("来源关联报告 %v（%v）；权限图规模：节点 %v / 边 %v；提权路径共 %v 条。路径表示一个低权限主体经角色、组成员等关系可实际到达的高权限终点，是单点问题之外的组合风险。",
			sec["correlation_report_id"], fmtTimeCN(fmt.Sprintf("%v", sec["generated_at"])), sec["nodes"], sec["edges"], sec["path_count"]), ""))
		if note, ok := sec["note"].(string); ok && note != "" {
			body.WriteString(grayPara(note))
		}
		prows := [][]string{{"风险", "路径链"}}
		if ps, ok := sec["paths"].([]any); ok {
			for _, pv := range ps {
				pm, ok := pv.(map[string]any)
				if !ok {
					continue
				}
				prows = append(prows, []string{riskCN(fmt.Sprintf("%v", pm["risk"])), fmt.Sprintf("%v", pm["chain"])})
			}
		}
		if len(prows) > 1 {
			body.WriteString(docxTableEx(prows, tableOpts{Widths: []int{900, 8600}, Header: true, FontSz: 19, MonoCols: map[int]bool{1: true}}))
		} else {
			body.WriteString(docxPara("该关联报告未发现提权路径。", ""))
		}
	}

	// ---------- 权限漂移 ----------
	if sec := snap.Drift; sec != nil {
		body.WriteString(secTitle("权限漂移（与上一事实包对比）"))
		body.WriteString(docxPara(fmt.Sprintf("对比基线包 %v；本次新增 %v 项、消失 %v 项，其中新增授权/角色关系 %v 项需重点关注。消失项通常为整改成果，新增项请逐项确认是否为授权变更。",
			sec["base_id"], sec["added_total"], sec["removed_total"], sec["attention"]), ""))
		if note, ok := sec["note"].(string); ok && note != "" {
			body.WriteString(grayPara(note))
		}
		drows := [][]string{{"方向", "类别", "主体", "明细"}}
		catCN := func(c string) string {
			switch c {
			case "privilege":
				return "权限"
			case "role_edge":
				return "角色关系"
			case "account":
				return "账号"
			case "config":
				return "配置"
			}
			return c
		}
		for _, dir := range []string{"added", "removed"} {
			itemsAny, ok := sec[dir].([]any)
			if !ok {
				continue
			}
			label := "新增"
			if dir == "removed" {
				label = "消失"
			}
			for _, iv := range itemsAny {
				im, ok := iv.(map[string]any)
				if !ok {
					continue
				}
				drows = append(drows, []string{label, catCN(fmt.Sprintf("%v", im["category"])),
					fmt.Sprintf("%v", im["subject"]), fmt.Sprintf("%v", im["detail"])})
			}
		}
		if len(drows) > 1 {
			body.WriteString(docxTableEx(drows, tableOpts{Widths: []int{800, 1300, 2200, 5200}, Header: true, FontSz: 19}))
		}
	}

	// ---------- 修复与回滚脚本 ----------
	if sec := snap.Remediation; sec != nil {
		body.WriteString(secTitle("修复与回滚脚本"))
		body.WriteString(docxPara(fmt.Sprintf("本报告不通过（FAIL）共 %v 条，已生成修复/回滚脚本 %v 条。每份脚本含前置检查、修复、验证与回滚四步，回滚为报告生成时捕获的精确逆操作。未生成脚本的为程序性整改项（配置流程、架构调整等），请按问题明细中的整改建议处理。",
			sec["fail_total"], sec["generated"]), ""))
		body.WriteString(paraRuns(runXML("重要：脚本仅供具备相应权限的工程师人工评审后执行，平台不会自动修改目标系统的任何权限。执行前请先完成前置检查并确认影响范围。", runStyle{Bold: true}), "", ""))
		scripts, _ := sec["scripts"].([]any)
		const docxCap = 100
		for i, sv := range scripts {
			if i >= docxCap {
				body.WriteString(grayPara(fmt.Sprintf("（其余 %d 条脚本见平台报告详情或 CSV 导出）", len(scripts)-docxCap)))
				break
			}
			sm, ok := sv.(map[string]any)
			if !ok {
				continue
			}
			rid := fmt.Sprintf("%v", sm["rule_id"])
			head := ruleName(rid) + " · " + fmt.Sprintf("%v", sm["subject"])
			if sc, _ := sm["scope"].(string); sc != "" {
				head += " · " + sc
			}
			body.WriteString(docxPara(head, "Heading3"))
			body.WriteString(grayPara("规则：" + rid))
			gets := func(k string) string {
				v, _ := sm[k].(string)
				return v
			}
			steps := []struct{ label, key string }{
				{"前置检查", "precheck"},
				{"修复命令", "fix"},
				{"验证", "verify"},
				{"回滚命令", "rollback"},
			}
			for _, st := range steps {
				if v := gets(st.key); v != "" {
					body.WriteString(leadPara(st.label+"：", ""))
					body.WriteString(codePara(v))
				}
			}
			if n := gets("note"); n != "" {
				body.WriteString(grayPara("备注：" + n))
			}
		}
	}

	// ---------- 附录 ----------
	body.WriteString(secTitle("附录：结论与状态说明"))
	body.WriteString(docxTableEx([][]string{
		{"不通过（FAIL）", "发现不符合安全要求的问题，需按整改建议处理并复检"},
		{"通过（PASS）", "该检查项符合安全要求"},
		{"未知（UNKNOWN）", "采集证据不足，无法判定，需人工确认"},
		{"未执行（NOT_RUN）", "该检查项本次未执行"},
		{"不适用（NOT_APPLICABLE）", "该检查项对本对象类型不适用"},
		{"完整（COMPLETE）", "采集执行完整，覆盖充分"},
		{"部分完成（PARTIAL）", "部分采集项被拒绝或截断，结论覆盖不完整"},
	}, tableOpts{Widths: []int{2600, 6900}, LabelFirst: true}))
	body.WriteString(docxPara("报告使用说明", "Heading2"))
	body.WriteString(docxPara("• 本报告为不可变快照，内容以报告生成时点的审计事实与评估结论为准，不随后续审计变化；重新导出将生成新的报告编号。", ""))
	body.WriteString(docxPara("• 整改完成后，请对审计对象重新审计，并在平台「复检对比」中确认问题已消除，直至问题清零。", ""))
	body.WriteString(docxPara("• 报告中的证据编号对应平台保存的采集事实，可由工程师在平台「审计记录」的工程师详情中溯源查看。", ""))

	footerLeft := ""
	if reportID != "" {
		footerLeft = "报告编号：" + reportID
	}
	return assembleDocx(body.String(), "内部敏感 · 请勿外传", footerLeft)
}

func kindFactCN(k string) string {
	switch k {
	case "identity":
		return "身份"
	case "privilege":
		return "权限"
	case "role_edge":
		return "角色关系"
	case "account_config":
		return "账号配置"
	case "service_config":
		return "服务配置"
	case "process":
		return "进程"
	case "database":
		return "数据库"
	}
	return k
}
