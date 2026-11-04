# re/out · 中间产物

| 文件 | 说明 |
|---|---|
| `pe_meta.json` | 11 个 PE 的段表 / 导出表 / 导入 DLL / TLS / Debug(PDB 路径) |
| `*_1.log.decoded` | 两份内核日志解密结果（XOR 0x8A） |
| `funcmap_kernel.dll.csv` | **反推符号表**：1531 个函数 → `func_rva, func_va, 函数名, 源码行号`（由日志宏帧还原，见 docs/05） |
| `funcnames_kernel.dll.txt` | 同上，按函数名检索更方便 |
| `logmap_limiter.txt` | 限速器代码区（0x2d8000–0x300000）里每个日志点的地址→文案映射 |
| `set_param_table.txt` | `set_parameter(type, value)` 的 147 项跳转表：type 编号 ↔ 参数名 |
| `YunLogic_config_template.txt` | YunLogic.dll 内嵌默认配置模板原文（含全部 `key="value"`） |
| `f_*.txt` | 关键函数的逐条反汇编（已注释字符串/调用目标） |

> `.gitignore` 忽略了 `f_*.txt` 之类的临时导出；需要时用 `re/tools/` 里的脚本重跑。
