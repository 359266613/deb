# 测试说明

运行基础测试：

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m pytest
```

建议自行放入真实 `.deb` 到 `samples` 后执行 smoke 分析。