# iOS 越狱 deb 插件逆向分析脚本

这是一套面向 iOS 越狱 `.deb` 插件包的静态逆向分析工具。默认不安装包、不执行 `preinst/postinst/prerm/postrm`，只做安全解包、control 元数据、文件树、哈希、维护脚本、字符串、plist、Mach-O、授权线索、偏好项、Substrate Hook 线索和可复刻移植方法分析。

## 快速开始

```powershell
.\scripts\setup-env.ps1
.\scripts\deb-analyze.ps1 -Input .\samples -Out .\outputs -DryRun
.\scripts\deb-analyze.ps1 -Input .\samples\plugin.deb -Out .\outputs
```

## 手上已有一个 deb 插件时怎么用

假设你的 deb 文件已经在本项目的 `samples` 目录：

```text
C:\Users\wyq\Desktop\opencode\deb插件逆向分析通用脚本\samples\plugin.deb
```

### 1. 进入脚本目录

```powershell
cd "C:\Users\wyq\Desktop\opencode\deb插件逆向分析通用脚本"
```

### 2. 初始化环境

第一次使用先执行一次：

```powershell
.\scripts\setup-env.ps1
```

如果之前已经成功执行过，可以跳过这一步。

### 3. 确认 deb 文件存在

当前示例使用的文件已经位于：

```text
.\samples\plugin.deb
```

执行下面命令确认路径有效：

```powershell
Test-Path ".\samples\plugin.deb"
```

返回 `True` 后继续下一步。

### 4. 先 dry-run 检查

```powershell
.\scripts\deb-analyze.ps1 -Input ".\samples\plugin.deb" -Out ".\outputs" -DryRun
```

或者直接使用完整路径：

```powershell
.\scripts\deb-analyze.ps1 -Input "C:\Users\wyq\Desktop\opencode\deb插件逆向分析通用脚本\samples\plugin.deb" -Out ".\outputs" -DryRun
```

`DryRun` 只检查输入、依赖和输出计划，不会解包分析。成功后会输出一个类似下面的目录：

```text
C:\Users\wyq\Desktop\opencode\deb插件逆向分析通用脚本\outputs\20260501T160000+0000
```

### 5. 正式分析

```powershell
.\scripts\deb-analyze.ps1 -Input ".\samples\plugin.deb" -Out ".\outputs"
```

或者：

```powershell
.\scripts\deb-analyze.ps1 -Input "C:\Users\wyq\Desktop\opencode\deb插件逆向分析通用脚本\samples\plugin.deb" -Out ".\outputs"
```

### 6. 查看结果

分析命令执行成功后，会在终端输出本次运行目录，例如：

```text
C:\Users\wyq\Desktop\opencode\deb插件逆向分析通用脚本\outputs\20260501T160754+0000
```

下面文档里的 `<run_id>` 是占位符，不能原样输入到 PowerShell。你需要把它替换成真实目录名，例如 `20260501T160754+0000`。

#### 方式一：直接打开刚才输出的目录

如果刚才输出的是：

```text
C:\Users\wyq\Desktop\opencode\deb插件逆向分析通用脚本\outputs\20260501T160754+0000
```

打开总览报告：

```powershell
notepad ".\outputs\20260501T160754+0000\report.md"
```

打开该批次的输出目录：

```powershell
explorer ".\outputs\20260501T160754+0000"
```

#### 方式二：自动打开最新一次分析报告

如果你不想手动复制 `run_id`，可以直接执行：

```powershell
$Run = Get-ChildItem ".\outputs" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
notepad (Join-Path $Run.FullName "report.md")
```

打开最新一次分析的目录：

```powershell
$Run = Get-ChildItem ".\outputs" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
explorer $Run.FullName
```

#### 方式三：打开单个 deb 的详细报告

单包详细报告在：

```text
outputs\<真实run_id>\packages\<真实package_id>\report.md
```

可以用 PowerShell 自动找到最新一次分析里的第一个单包报告：

```powershell
$Run = Get-ChildItem ".\outputs" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$PkgReport = Get-ChildItem (Join-Path $Run.FullName "packages") -Filter "report.md" -Recurse | Select-Object -First 1
notepad $PkgReport.FullName
```

其中：

- `outputs\<真实run_id>\report.md` 是本次运行的总览报告
- `outputs\<真实run_id>\packages\<真实package_id>\report.md` 是单个 deb 的详细分析报告

需要深入分析时，再看这些结构化结果：

```text
outputs\<run_id>\packages\<package_id>\metadata.json
outputs\<run_id>\packages\<package_id>\filetree.json
outputs\<run_id>\packages\<package_id>\scripts.json
outputs\<run_id>\packages\<package_id>\strings.json
outputs\<run_id>\packages\<package_id>\binaries.json
outputs\<run_id>\packages\<package_id>\findings.json
outputs\<run_id>\packages\<package_id>\hashes.json
```

建议优先顺序：

1. `report.md`
2. `findings.json`
3. `scripts.json`
4. `strings.json`
5. `filetree.json`
6. `binaries.json`
7. `metadata.json`

### 7. 查看解包后的原始文件

脚本会把 deb 静态解包到：

```text
outputs\<run_id>\packages\<package_id>\extracted\
```

主要目录：

```text
extracted\control\
extracted\data\
```

重点关注：

- `extracted\control\control`
- `extracted\control\preinst`
- `extracted\control\postinst`
- `extracted\control\prerm`
- `extracted\control\postrm`
- `extracted\data\Library\MobileSubstrate\DynamicLibraries\`
- `extracted\data\var\jb\Library\MobileSubstrate\DynamicLibraries\`
- `extracted\data\Library\PreferenceBundles\`
- `extracted\data\var\jb\Library\PreferenceBundles\`
- `extracted\data\Library\PreferenceLoader\Preferences\`
- `extracted\data\var\jb\Library\PreferenceLoader\Preferences\`

### 8. 批量分析多个 deb

把多个 `.deb` 放进 `samples`：

```text
samples\a.deb
samples\b.deb
samples\c.deb
```

然后执行：

```powershell
.\scripts\deb-analyze.ps1 -Input ".\samples" -Out ".\outputs"
```

### 9. 新旧版本差异对比

```powershell
.\scripts\deb-diff.ps1 -Old ".\samples\old.deb" -New ".\samples\new.deb" -Out ".\outputs\diff"
```

查看：

```text
outputs\diff\diff.md
outputs\diff\diff.json
```

差异结果会包含 control 元数据变化、文件新增、文件删除、文件修改和 hash 变化。

### 10. 结果判断重点

优先看 `report.md` 和 `ios_analysis.json` 中这些内容：

- `授权逻辑初判`：判断是否存在设备码、许可证、验签、联网授权等逻辑
- `授权相关证据`：定位许可证 UI、设备指纹、加密验签、联系信息所在文件
- `Tweak 注入 Bundles/Executables`：确认插件注入目标
- `Mach-O 摘要`：确认核心 dylib、设置 bundle 二进制和架构
- `偏好项/设置读写线索`：定位 `NSUserDefaults`、`CFPreferences`、`PSSpecifier` 等配置入口
- `Hook / Substrate 线索`：定位 `MobileSubstrate`、`Logos`、`SpringBoard` 等 Hook 入口
- `可复刻移植方法`：按安装布局、注入目标、设置面板、授权状态机和验证步骤复刻

### 11. 常见问题

如果 PowerShell 提示脚本不能运行，当前窗口执行：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

如果找不到 deb，先检查路径：

```powershell
Test-Path ".\samples\plugin.deb"
```

返回 `True` 才表示路径正确。

如果终端里中文路径显示乱码，通常只影响控制台显示，不影响 `outputs` 目录下的结果文件。

## 差异对比

```powershell
.\scripts\deb-diff.ps1 -Old .\samples\old.deb -New .\samples\new.deb -Out .\outputs\diff
```

`-Old` 和 `-New` 可以是 `.deb` 文件，也可以是已经生成过的单包分析目录。

## 输出

每次运行会生成：

```text
outputs\<run_id>\
  manifest.json
  plan.json
  summary.json
  summary.csv
  report.md
  packages\<package_id>\
    input.json
    metadata.json
    filetree.json
    scripts.json
    strings.json
    binaries.json
    hashes.json
    findings.json
    report.md
    extracted\control\
    extracted\data\
```

## 安全边界

- 不调用 `dpkg -i` 或 `apt install`
- 不执行 deb 内维护脚本
- 解包时阻断绝对路径、`..` 路径和符号链接物化
- 单包失败不会中断整个批次

## 可选增强工具

如果系统中存在 `file`，报告会补充 Mach-O 文件类型识别。缺失时会自动降级为 Python 内置 Mach-O 头部识别。