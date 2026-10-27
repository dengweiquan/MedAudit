# rulesets 说明

本目录是**全部内置规则**的元数据（文本/版本/风险/整改建议），每条规则一个
YAML，供查阅、评审与对外交付。运行时真相是 `internal/rules` 的 Go 内置
规则，本目录由 `rules.MetadataYAML` 生成，**不要手改**。

规则文本或版本变更后重新生成：

```
go test ./internal/rules -run Rulesets -update
```

CI 中 `TestRulesetsInSync` 会逐字比对，YAML 与内置规则不一致、多出或缺失
都会失败。
