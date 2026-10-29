# tools

所有 Python 脚本只用 **Python 3.8 标准库**（DSM 7 自带），可以在 NAS 上以 `python3 - ARGS < script.py` 从 stdin 运行，不在 NAS 上留文件。`make_selftest.py` 例外，它在分析机上运行并需要 `cryptography`。`keyscan.c` 在 macOS 上编译（CommonCrypto）。

命令示例和占位符见 [docs/00-runbook.md](../docs/00-runbook.md)。

## 只读保证

| 对象 | 保证 |
|---|---|
| 块设备（LV） | 只用 `os.open(dev, O_RDONLY)` + `pread`；没有任何写调用 |
| `/proc/kcore` | 只读 |
| 被加密的 `.L0CK3D` 文件 | 只以 `"rb"` 打开 |
| 输出 | 要么写到 stdout（经 SSH 回到分析机），要么由 `extract_jobs.py` 用 `O_CREAT\|O_EXCL` 新建到你指定的目录（**应在另一个卷上**）；已存在的文件不会被覆盖 |
| `btrfs_restore_run.sh` | 调用 `btrfs restore`，它只读源设备；输出目录必须不存在（`mkdir` 失败即退出） |

脚本不会自己检查「输出目录是否在另一个卷」，这一点由操作者保证。

## 输出里的敏感内容

`collect_footers.py` 的输出含每个文件的 `footer[0:48]`（被包裹的文件密钥记录）、文件开头 16 字节和完整路径；`walk_tree.py` / `parse_leaves.py` 的输出含全部文件名；`keyscan` 命中时打印候选密钥。**这些都是私有证据，不要公开**，`.gitignore` 已排除常见文件名。

## 逐个说明

### 内存

| 脚本 | 运行位置 | 输入 | 输出 |
|---|---|---|---|
| `kcore_dump.py` | NAS（root） | `/proc/kcore`；`--list` 只列段 | stdout：LiME 格式镜像；stderr：段列表、进度、`HOLE`、`DONE bytes=… unreadable_pages=…` |
| `keyscan.c` | 分析机（macOS） | `RAM.lime`、`FOOTERS.bin`（N×48 字节 `footer[0:48]`）、线程数 | stdout：每个命中一行 `HIT footer= off= paddr= key= prev16= nonce=`；stderr：进度、候选数 |
| `make_selftest.py` | 分析机 | 输出目录、大小（MiB） | `planted.lime`、`blank.lime`、`footers.bin`、`expect.txt`（全部合成数据） |

`keyscan` 的前置过滤：32 字节窗口内不同字节数 ≥ 22 才做 AES（`MIN_DISTINCT`）；校验：第三块解密后前 8 字节 = 后 8 字节（64 位）。

### 普查

| 脚本 | 运行位置 | 输入 | 输出 |
|---|---|---|---|
| `collect_footers.py` | NAS（root） | `ROOT`、`MAX_FILES` | JSON lines：`path size mtime marker mode pct crypto orig rec head`。跳过 `@eaDir`、符号链接、小于 588 字节的文件 |

### btrfs 元数据

| 脚本 | 运行位置 | 输入 | 输出 |
|---|---|---|---|
| `chunkmap.py` | 分析机 | `btrfs-debug-tree -t 3`（或 `dump-tree -t chunk`）的文本输出 | `logical length physical type` 行。只支持单盘 SINGLE/DUP，RAID 条带 chunk 跳过并报告 |
| `walk_tree.py` | NAS（root） | `DEVICE`（LV）、`CHUNKMAP`、`SUBVOL_ID` | JSON lines：当前 fs tree 的 `inode` / `ref` / `ext` 记录，带叶子 generation 和地址；stderr：叶子数、跳过的坏节点 |
| `parse_leaves.py` | NAS（root） | `DEVICE`、`CHUNKMAP`、`LEAFLIST`（`gen level bytenr`，来自 `btrfs-find-root -a -o`）、`OWNER`（子卷 ID） | 同上格式，另含 `dir`（DIR_INDEX）；只解析块头 `bytenr`/`owner`/`level` 校验通过的 level-0 叶子 |

节点大小在 `walk_tree.py` 中从 superblock 读取；`parse_leaves.py` 固定为 16 KiB（btrfs 默认），如果你的卷不同请修改 `NODESIZE`。

### 任务与恢复

| 脚本 | 运行位置 | 输入 | 输出 |
|---|---|---|---|
| `make_jobs2.py`（主用） | 分析机 | 当前树 items、孤儿叶子 items（可为空文件）、`CUTOFF`、加密文件清单（`size<TAB>相对路径.L0CK3D`）、`PREFIX`（目标目录相对子卷根，如 `USER/Photos/`） | `jobs.jsonl`：`{"rel", "ino", "extents": [[foff, disk_bytenr, eoff, nbytes], …]}`，精确旧引用在前、整 extent 合成在后；stdout：统计 |
| `make_jobs.py` | 分析机 | 孤儿叶子 items、`CUTOFF`、清单、`PREFIX` | 同格式，只含孤儿叶子的精确引用（早期版本，保留作对照） |
| `build_plan.py` | 分析机 | 孤儿叶子 items、`CUTOFF`、`PREFIX`、[清单] | 只列出旧引用能完整覆盖整个文件的计划（最早的探索版本，不处理部分加密拼接） |
| `extract_jobs.py` | NAS（root） | `DEVICE`、`CHUNKMAP`、`TARGET_ROOT`（现存 `.L0CK3D` 所在目录）、`JOBS`、`OUT_DIR`、`PARTIAL_DIR` | 恢复出的文件写到 `OUT_DIR` / `PARTIAL_DIR`；stdout 每文件一行 JSON：`status`（OK / OK_UNVERIFIED / PARTIAL / FAIL / EXISTS / ERR）、`cover`、`magic`、`same_as_cipher` |
| `btrfs_restore_run.sh` | NAS（root） | `LV_DEVICE`、`OUT_DIR`、`PATH_REGEX`、若干 `ROOT_BYTENR` | `OUT_DIR` 下恢复出的文件；`OUT_DIR.log` |

`extract_jobs.py` 的关键规则：

- 加密范围按页脚的模式和 pct 计算（`PARTIAL_FACTORS` 来自 soimy 的分段规则）。
- 只填仍标记为加密的字节；**读回内容与现存密文相同则拒绝**。
- 超过 `MAX_SIZE`（1.5 GiB）的文件报 `ERR BIG`，需要流式版本。
- 整个文件会读入内存，单文件内存占用约为文件大小的 2 倍。

### 验证

| 脚本 | 运行位置 | 输入 | 输出 |
|---|---|---|---|
| `verify_restored.py` | NAS 或分析机 | `ROOT`、[会话标记，默认 `0b5c8e4c`] | TSV：`状态  大小  相对路径`；状态为 `OK_<格式>` / `ENCRYPTED`（末尾仍是本会话页脚）/ `ZEROS` / `UNKNOWN` / `EMPTY`。**仅文件头检查** |

## 不包含的东西

- soimy 的 `decrypt_copy.py`：版权归原作者，不收录。本案的一行改动见 [docs/02](../docs/02-memory-capture-and-keyscan.md#五如果你扫到了soimy-解密器的一行改动)。
- 任何样本、真实镜像、页脚记录、文件清单或恢复结果。

## 流式大文件与合并

| 脚本 | 作用 | 只读保证 |
|---|---|---|
| `extract_big.py` | `extract_jobs.py` 的流式版，按 32 MiB 分块处理 >1.5 GiB 的文件，内存占用固定；`MIN_PARTIAL_COVER` 环境变量控制部分恢复的写出门槛 | 只读裸设备和现存文件；先写 `.tmp` 再改名，目标已存在则跳过 |
| `merge_exec.py` | 按合并计划用 `FICLONE`（reflink）把每个文件的最佳来源克隆到最终目录，不占额外空间；JPEG/PNG 可选校验结尾标记 | 源文件不动；目标 `O_EXCL` |

## 视频修复（`video/`，详见 [docs/06](../docs/06-video-repair.md)）

| 脚本 | 运行位置 | 作用 |
|---|---|---|
| `movsamples.py` | 任意 | 解析 `moov` 样本表（`stsz`/`stco`/`co64`/`stsc`/`stts`/`stss`），逐样本做 NAL 长度框架校验；算坏帧时间段、加密段对应的时间段 |
| `videofix.py` | NAS（root） | 由 `mdat` 头推出 `moov` 偏移和长度，在已知 extent 附近的裸设备上搜 `be32(size)+"moov"`，补回尾部；只保留逐帧校验通过的最长后缀 |
| `headerfix.py` | NAS（root） | 头部整段丢失时找 `moov`（文件尾或裸设备上的 `moov`+`mvhd`），用明文区样本校验（≥80%）后重建 `ftyp`/`free`/`mdat` 头并把 `moov` 接到文件尾；临时目录用 `WORK_TMP` |
| `gapfill.py` | NAS（root） | 逐帧在裸设备上找回中段数据（4 KiB 对齐 + 单 NAL 长度前缀作检索键）。**本案无收获**，留作参考 |
| `finish_videos2.py` | macOS | 拉回视频 → 逐轨道完整解码 → 跳过坏段无损拼接（失败落在加密段内则整段跳过）→ 再校验 → 推回 NAS；SSH 目标用 `NAS_SSH` 环境变量 |
| `checkvideo.swift` | macOS | 每条轨道单独 `AVAssetReader` 完整解码，报告每条轨道读到的位置和失败点（按 track ID，避免两条音频轨互相覆盖） |
| `splicevideo.swift` / `trimvideo.swift` | macOS | `AVMutableComposition` + passthrough 导出：按时间段无损拼接 / 截取，不重新编码 |

编译：`swiftc -O -o checkvideo checkvideo.swift`（另外两个同理）。
