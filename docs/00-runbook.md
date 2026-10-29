# 00 · 操作手册：按顺序执行的命令

本篇只写「做什么、怎么做、做完看什么」。原理见 [02](02-memory-capture-and-keyscan.md) 和 [03](03-btrfs-extent-retention.md)。

## 占位符

| 占位符 | 含义 | 怎么得到 |
|---|---|---|
| `NAS_IP` | NAS 地址 | — |
| `USER` | 能 SSH 登录、可 sudo 的 DSM 账号 | — |
| `/volume1` | 被加密的卷 | `df -h` |
| `/volume2` | **另一个**有足够空间的卷，所有输出都放这里 | `df -h` |
| `/dev/mapper/vgN-volume_N` | `/volume1` 底下的 LVM 逻辑卷 | 第 5 步 |
| `/dev/mapper/cachedev_N` | DSM 实际挂载的设备（flashcache 包装层） | `mount \| grep volume1` |
| `TARGET` | 被加密的目录，例如 `/volume1/homes/USER/Photos` | — |
| `PREFIX` | `TARGET` 相对于所在子卷根的路径，例如 `USER/Photos/`（`homes` 是一个子卷） | `btrfs subvolume list /volume1` |
| `SUBVOL_ID` | `TARGET` 所在子卷的 ID | 同上 |
| `CUTOFF` | 攻击开始时的 btrfs generation | 第 6 步 |
| `ROOT_BYTENR` | 一个旧 fs-tree 根块的逻辑地址 | 第 7 步 |
| `WORK` | NAS 上的工作目录，如 `/volume2/rescue_work`（在另一卷上） | 自建 |

约定：`ssh` 命令在**分析机**上执行，脚本通过 `python3 -` 从 stdin 送到 NAS，NAS 上不留脚本文件；大输出经 SSH 回传到分析机。分析机上需要 Python 3.8+；`keyscan.c` 需要 macOS（CommonCrypto）。

### 前置：免交互 sudo（临时）

`ssh … 'sudo python3 -' < script.py` 的 stdin 已被脚本占用，sudo 无法读密码。本案用 SSH 密钥登录 + 一个临时 sudoers 片段：

```sh
# 在 NAS 上交互执行一次（会要求密码）
echo 'USER ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/zz-ir-temp
sudo chmod 440 /etc/sudoers.d/zz-ir-temp
# 处置结束后必须删除：sudo rm /etc/sudoers.d/zz-ir-temp
```

这是一个风险敞口，只在处置窗口内保留，结束后删除（见 [05](05-hardening.md)）。

---

## 1. 加密进程还在不在

状态：**已验证（本案：进程已不在）**

```sh
ssh USER@NAS_IP 'sudo sh -c "ls -l /proc/*/exe 2>/dev/null | grep deleted"'
# 对每个可疑 PID：
ssh USER@NAS_IP 'sudo sh -c "tr \"\\0\" \" \" < /proc/PID/cmdline; echo; ls -l /proc/PID/exe; cat /proc/PID/status | head -8"'
ssh USER@NAS_IP 'sudo netstat -tnp 2>/dev/null | grep ESTABLISHED'
```

- 有加密器进程 → **不要 kill、不要重启**。`kill -STOP PID` 冻结后按 [soimy](https://github.com/soimy/c3rb3r-rescue) / [Benjamin-zlt](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue) 的流程取进程内存，这是唯一能全解的路。
- 本案：唯一指向已删除文件的是 5 个 root `inetd`，来自引导器的 busybox（开机即启动，监听 23 端口 telnet），**不是加密器**，但它是暴露面（见 05）。加密器已退出约 27 小时。
- 同时查持久化：**看内容不看文件名**（`cat /etc/cron.d/*`、`ls -la /etc/cron.d`）。

## 2. 停掉写入该卷的套件

状态：**已验证**。越早越好，bookend 方法依赖旧 extent 不被搬动或复用。

```sh
ssh USER@NAS_IP '/usr/syno/bin/synopkg list --name 2>/dev/null || ls /var/packages'
# synopkg 不在 sudo 的 secure_path 里，必须写全路径
ssh USER@NAS_IP 'for p in SynologyPhotos SynologyDrive CloudSync DownloadStation SurveillanceStation; do sudo /usr/syno/bin/synopkg stop $p; done'
```

包名以你机器上的 `list` 输出为准。本案停了相册、Drive、Cloud Sync、Download Station、Surveillance Station。**不要**在恢复完成前对该卷做 balance、碎片整理、存储空间回收或删快照。

## 3. 整机内存采集

状态：**方法已验证可用；本案未取得密钥**

```sh
# 先列段，确认能读、总量合理
ssh USER@NAS_IP 'sudo python3 - --list' < tools/kcore_dump.py
# 流式拉回分析机（NAS 上不落盘），stderr 是进度与不可读页统计
ssh USER@NAS_IP 'sudo python3 -' < tools/kcore_dump.py > ram.lime 2> dump.log
tail -2 dump.log           # 期望: TOTAL … / DONE bytes=… unreadable_pages=0
shasum -a 256 ram.lime > ram.lime.sha256
```

本案：15.86 GiB、5 段、0 不可读页、约 100 MB/s。zram 未单独采集（见 02 的局限）。

## 4. 页脚普查

状态：**已验证，必做**

```sh
ssh USER@NAS_IP 'sudo python3 - /volume1/homes/USER/Photos 10000000' < tools/collect_footers.py > footers.jsonl
# 汇总：会话标记、加密模式、文件模式分布
python3 - footers.jsonl <<'EOF'
import json, sys, collections
c, b, mk, cr = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
for l in open(sys.argv[1]):
    r = json.loads(l); k = (hex(r["mode"]), r["pct"]); c[k] += 1; b[k] += r["size"]
    mk[r["marker"]] += 1; cr[hex(r["crypto"])] += 1
print("markers", dict(mk), "crypto", dict(cr))
for k in sorted(c): print(k, c[k], "%.1f GiB" % (b[k] / 2**30))
EOF
```

读结果：

- `0x26`（仅前 1 MiB）和 `0x25`（分段）→ 在 btrfs 上大概率能用第 8 步救回。
- `0x24`（整文件）→ 只能靠第 7 步和孤儿叶子，期望很低。
- 会话标记不止一个 → 分开处理。标记与已公开密钥的会话不同 → 那把密钥不适用。

`footers.jsonl` 含每个文件的 `footer[0:48]`，属于私有证据，**不要公开**。

## 5. 密钥扫描（先自检）

状态：**方法已验证可用；本案 NO_MATCH**

```sh
clang -O2 -o keyscan tools/keyscan.c
# 自检：合成镜像 + 埋入合成主密钥（需要 pip install cryptography）
python3 tools/make_selftest.py selftest
./keyscan selftest/planted.lime selftest/footers.bin 4    # 必须恰好 1 行 HIT，off 等于 selftest/expect.txt
./keyscan selftest/blank.lime   selftest/footers.bin 4    # 必须 0 行 HIT
# 正式扫描：取几个不同文件的 footer[0:48]
python3 -c 'import json,sys; L=open("footers.jsonl").readlines()[:3]; sys.stdout.buffer.write(b"".join(bytes.fromhex(json.loads(l)["rec"]) for l in L))' > footers.bin
./keyscan ram.lime footers.bin 10 > hits.txt 2> scan.log
wc -l hits.txt
```

命中后用 soimy 的 `decrypt_copy.py` 对**副本**解密；它的会话标记写死为 `ce35a593`，需要改一行（见 02）。

## 6. 找底层 LV，对上 generation 和时间

状态：**已验证有效**

```sh
ssh USER@NAS_IP 'mount | grep " /volume1 "; sudo lvs 2>/dev/null; ls -l /dev/mapper/'
# 当前 superblock generation（btrfs-progs 4.x 用 btrfs-show-super）
ssh USER@NAS_IP 'sudo btrfs-show-super /dev/mapper/vgN-volume_N 2>/dev/null | grep ^generation || sudo btrfs inspect-internal dump-super /dev/mapper/vgN-volume_N | grep ^generation'
ssh USER@NAS_IP 'sudo btrfs subvolume list /volume1'          # → SUBVOL_ID
# 用 mtime 已知的文件（如第一封勒索信 read-me3.txt）对上 generation：
ssh USER@NAS_IP 'sudo btrfs subvolume find-new /volume1/homes GEN_LOW | grep read-me3.txt | head'
```

`find-new` 每行带 `gen N`。最早一封勒索信的 generation 就是 `CUTOFF`（本案约 18141074）。比 `CUTOFF` 小的 extent 一定是攻击前写入的。

## 7. 旧 fs-tree 根恢复（`btrfs restore`）

状态：**已验证有效**（本案 2,442 个文件 / 19.9 GiB 头部校验通过）

`btrfs restore` 拒绝已挂载设备；**对底层 LV 运行**，它只读 LV，输出写到另一卷。

```sh
# 7a. 找该子卷的所有候选树块（可能要几十分钟）
ssh USER@NAS_IP 'sudo btrfs-find-root -a -o SUBVOL_ID /dev/mapper/vgN-volume_N' > find-root.txt 2>&1
# 转成 "gen level bytenr"，按 generation 排序（正则按你的 btrfs-progs 输出调整）
sed -nE 's/.*block ([0-9]+)\(gen: ([0-9]+) level: ([0-9]+)\).*/\2 \3 \1/p' find-root.txt | sort -n -u > leaves.txt
awk '{print $2}' leaves.txt | sort | uniq -c        # 本案: level0 19,626 / level1 343 / level2 67

# 7b. 挑 generation 略大于 CUTOFF、level 最高的根，逐个 dry-run，看能列出多少文件
ssh USER@NAS_IP "sudo btrfs restore -D -v -i -f ROOT_BYTENR --path-regex '^/(|USER(|/Photos(|/.*)))\$' /dev/mapper/vgN-volume_N /volume2/unused" > dry-ROOT_BYTENR.txt 2>&1
grep -c '^Restoring' dry-ROOT_BYTENR.txt

# 7c. 用最好的几个根真正恢复（输出目录必须在另一卷且不存在）
ssh USER@NAS_IP "sudo sh -s /dev/mapper/vgN-volume_N /volume2/rescue_restore '^/(|USER(|/Photos(|/.*)))\$' ROOT_BYTENR_1 ROOT_BYTENR_2 ROOT_BYTENR_3" < tools/btrfs_restore_run.sh
```

本案用了 3 个约 14:55 的根（generation 18141107 / 18141129 / 18141132，在勒索信之后、照片目录开始加密之前）。

**不要这样做**：`btrfs restore -t <旧 root tree> -r SUBVOL_ID` —— 本案旧 root tree 里指向该子卷的指针所指块已被覆盖，结果 0 个文件。直接用 `-f` 指 fs-tree 根。

## 8. 核心：bookend extent 合成

状态：**已验证有效**（中期 6,082/6,217 完整恢复；`0x25`/`0x26` 接近 100%）

```sh
# 8a. chunk 映射（逻辑地址 → 物理偏移），只支持单盘 SINGLE/DUP
ssh USER@NAS_IP 'sudo btrfs-debug-tree -t 3 /dev/mapper/vgN-volume_N' > chunk-tree.txt   # 新版: btrfs inspect-internal dump-tree -t chunk
python3 tools/chunkmap.py chunk-tree.txt > chunkmap.txt
ssh USER@NAS_IP 'mkdir -p /volume2/rescue_work' && scp chunkmap.txt leaves.txt USER@NAS_IP:/volume2/rescue_work/

# 8b. 遍历当前 fs tree（从 superblock 出发，只读 LV）
ssh USER@NAS_IP 'sudo python3 - /dev/mapper/vgN-volume_N /volume2/rescue_work/chunkmap.txt SUBVOL_ID' < tools/walk_tree.py > items-current.jsonl
# 8c. 解析孤儿叶子（第 7a 步找到的 level 0 块），补 0x24 的精确引用
ssh USER@NAS_IP 'sudo python3 - /dev/mapper/vgN-volume_N /volume2/rescue_work/chunkmap.txt /volume2/rescue_work/leaves.txt SUBVOL_ID' < tools/parse_leaves.py > items-orphan.jsonl

# 8d. 现存加密文件清单（size<TAB>相对 TARGET 的路径）
python3 -c 'import json,os,sys
for l in open("footers.jsonl"): r=json.loads(l); print("%d\t%s" % (r["size"], os.path.relpath(r["path"], sys.argv[1])))' /volume1/homes/USER/Photos > encrypted-list.tsv

# 8e. 生成任务：精确旧引用在前，整 extent 合成引用在后
python3 tools/make_jobs2.py items-current.jsonl items-orphan.jsonl CUTOFF encrypted-list.tsv USER/Photos/ jobs.jsonl
scp jobs.jsonl USER@NAS_IP:/volume2/rescue_work/

# 8f. 先拿几十个任务试跑，确认 OK 比例后再全量
head -50 jobs.jsonl > jobs-test.jsonl && scp jobs-test.jsonl USER@NAS_IP:/volume2/rescue_work/
ssh USER@NAS_IP 'sudo nice -n 10 python3 - /dev/mapper/vgN-volume_N /volume2/rescue_work/chunkmap.txt /volume1/homes/USER/Photos /volume2/rescue_work/jobs-test.jsonl /volume2/rescue_test/ok /volume2/rescue_test/partial' < tools/extract_jobs.py > extract-test.jsonl
python3 -c 'import json,collections; print(collections.Counter(json.loads(l)["status"] for l in open("extract-test.jsonl")))'

# 8g. 全量（可放 nohup/screen；输出目录在另一卷，已存在的文件不会被覆盖）
ssh USER@NAS_IP 'sudo nice -n 10 python3 - /dev/mapper/vgN-volume_N /volume2/rescue_work/chunkmap.txt /volume1/homes/USER/Photos /volume2/rescue_work/jobs.jsonl /volume2/rescue_extent/ok /volume2/rescue_extent/partial' < tools/extract_jobs.py > extract-report.jsonl
```

报告里每个文件一行：`OK`（全部加密字节已被旧 extent 覆盖且文件头像样）、`OK_UNVERIFIED`（部分加密模式、覆盖完整但文件头不认识）、`PARTIAL`（覆盖 ≥50%，缺口填零，放 `partial/`）、`FAIL`、`ERR`（含 `BIG`：超过 1.5 GiB 的文件，需要流式版本，本案 32 个）。

## 9. 验证

状态：**已验证（格式级）**

```sh
# 9a. 文件头分类（只读）
ssh USER@NAS_IP 'sudo python3 - /volume2/rescue_extent/ok' < tools/verify_restored.py > verify.tsv
cut -f1 verify.tsv | sort | uniq -c        # OK_jpeg / OK_heic / ... / ENCRYPTED / ZEROS / UNKNOWN / EMPTY

# 9b. 抽样拉回分析机，用 macOS ImageIO 强制完整解码（转码会读完整个码流）
mkdir -p sample decoded
# … 随机挑 40 个图片 scp 到 sample/ …
for f in sample/*; do sips -s format png "$f" --out "decoded/$(basename "$f").png" >/dev/null 2>&1 && echo OK || echo "BAD $f"; done | sort | uniq -c
# 9c. 目视检查 decoded/ 里的图片：有无灰块、错位、半截
```

报告时写明验证等级（沿用 soimy 的用语）：文件头 = 「语法或文件头」；图像完整解码 + 目视 = 介于「完整归档/压缩检查」和「语法或文件头」之间；**都不是「历史 SHA 完全一致」**。视频本案只做了文件头。

## 10. 收尾

- 删除临时 sudoers：`sudo rm /etc/sudoers.d/zz-ir-temp`。
- `.L0CK3D` 原件全部保留，不要覆盖，将来如果出现针对 `0b5c8e4c` 会话的密钥还可以再解。
- 恢复结果确认后再重启被停的套件；相册套件重新索引会大量写盘，确认不再需要从该卷捞旧 extent 之后再开。
- 加固见 [05](05-hardening.md)。
