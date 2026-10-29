# 03 · btrfs extent 残留：不用密钥恢复部分加密的文件

这是本仓库的核心。一句话：**C3RB3R 对大文件只原地加密一部分；btrfs 写时复制只为被改写的部分分配新空间，而原来的 extent 只要还有一个字节被引用，就整块保留——被加密之前的那几段原文也在里面。**

## 一、btrfs 怎么记录文件内容（只讲用到的部分）

- 文件数据存放在 **extent** 里：磁盘上一段连续空间，由逻辑地址 `disk_bytenr` 和长度 `disk_num_bytes` 描述。数据 extent 最大 128 MiB，大文件由多个 extent 组成。
- 每个子卷有一棵 **fs tree**。文件的每一段内容对应一条 `EXTENT_DATA` 记录，键是「inode 号 + 文件内偏移 `foff`」，值里有：
  - `generation`：这个 extent 被写入时的事务号（下称 `egen`）
  - `disk_bytenr`、`disk_num_bytes`：指向哪个 extent、这个 extent 整体多大
  - `offset`（下称 `eoff`）、`num_bytes`：本记录用的是 extent 里从 `eoff` 开始的 `num_bytes` 字节
- 一个 extent 是否被释放，看的是**整个 extent 还有没有任何引用**，而不是它的每个字节有没有被引用。只引用了 extent 一部分的记录俗称 **bookend**；extent 中不再被任何文件引用的那部分空间，在整个 extent 被释放之前一直是「已分配」状态。
- **写时复制（CoW）**：改写文件某个范围时，新数据写到新分配的 extent，fs tree 里那个范围的记录改为指向新 extent；旧 extent 不被覆盖。

## 二、C3RB3R 的部分加密遇上 CoW

页脚格式和分段规则来自 soimy 的分析：`0x26` 只加密前 1 MiB；`0x25` pct=10 在头、中、尾各加密 4%；`0x24` 整文件加密。部分加密模式是**原地改写**（同一个 inode，改写加密段、在末尾追加 588 字节页脚、再改名加 `.L0CK3D`）。本案的直接证据是：现存 `.L0CK3D` 文件的 fs tree 记录里，仍有 `egen` 早于攻击开始的 extent 引用。

### 图示：一个 4 MiB 的照片被 `0x26` 加密前后

```
攻击前
  fs tree   foff 0 ─────────────────────────────────────────── 4 MiB
            EXTENT_DATA foff=0  → X  eoff=0  num=4 MiB   egen < CUTOFF
  磁盘      X: [  P0 (1 MiB)  |  P1  |  P2  |  P3  ]     ← 原文

加密器原地改写前 1 MiB，追加页脚
  fs tree   EXTENT_DATA foff=0      → Y  eoff=0      num=1 MiB  egen ≥ CUTOFF   （新 extent，密文）
            EXTENT_DATA foff=1 MiB  → X  eoff=1 MiB  num=3 MiB  egen < CUTOFF   ← bookend
            EXTENT_DATA foff=4 MiB  → Z  （588 字节页脚）
  磁盘      Y: [  C0 (1 MiB 密文) ]
            X: [  P0 (1 MiB)  |  P1  |  P2  |  P3  ]     ← 整块仍是「已分配」
                 ^^^^^^^^^^^^
                 不再被任何文件引用，但 X 还有引用（P1..P3），所以不能释放，也不会被覆盖

恢复
  从 bookend 记录 (foff=1 MiB, eoff=1 MiB) 反推出整个 extent 的原始位置：
      文件偏移 = foff − eoff = 0，     extent 内偏移 = 0，     长度 = disk_num_bytes = 4 MiB
  读 X[0 : 1 MiB] = P0，覆盖到现存文件的 [0, 1 MiB)，去掉页脚 → 原文件
```

`0x25` 同理：三个加密段各落在某个 extent 内部时，这个 extent 两侧的明文仍被引用，整块保留，三段原文都能读回。

### 什么时候不灵

| 情况 | 结果 |
|---|---|
| `0x24` 整文件加密 | 文件所有范围都被改写，旧 extent 失去全部引用 → **被释放**，空间可能已被后续写入复用。只能从孤儿叶子拿到旧引用，再碰运气读回 |
| 加密段完整覆盖了一个或多个 extent | 被完整覆盖的 extent 同样失去全部引用而被释放。对 `0x25` 来说，只有当 4% 的段长超过单个 extent 的长度（大约几 GB 以上的视频）时才会发生；本案 9 个 PARTIAL 全部是 `0x25` 大文件，与此一致（推断，未逐个核实） |
| 文件或目录设置了 NOCOW（`chattr +C`） | 改写直接覆盖原位置，没有残留 |
| extent 被压缩 | 工具跳过压缩 extent（DSM 默认不开压缩，本案没有） |
| 停写入太晚、卷接近满、做过 balance/defrag | 旧 extent 被搬走或释放后复用 |

## 三、流程

```
superblock ──► root tree ──► 目标子卷的 fs tree 根
                                   │  walk_tree.py：遍历当前 fs tree 的全部叶子（只读 LV）
                                   ▼
                      items-current.jsonl  (INODE_ITEM / INODE_REF / EXTENT_DATA)
btrfs-find-root -a -o SUBVOL_ID ──► leaves.txt ──► parse_leaves.py ──► items-orphan.jsonl
                                                                         │
encrypted-list.tsv (来自页脚普查) ────────────────┐                       │
                                                  ▼                       ▼
                                   make_jobs2.py：按路径匹配现存 .L0CK3D，组装 extent 列表
                                                  │
                                                  ▼
                                   extract_jobs.py：读页脚算加密范围 → 从 LV 读旧字节 → 拼接 → 写到另一卷
```

### 1. chunk 映射

btrfs 内部用逻辑地址，读 LV 要先换算成物理偏移。`btrfs-debug-tree -t 3`（新版 `btrfs inspect-internal dump-tree -t chunk`）导出 chunk tree，`tools/chunkmap.py` 转成 `logical length physical type` 表。本案是单盘 SINGLE 数据 + DUP 元数据，stripe 0 即可；RAID 条带需要另写换算。

### 2. 遍历当前 fs tree（`walk_tree.py`）

从 superblock（LV 偏移 64 KiB）读出 root tree 地址 → 在 root tree 里找目标子卷的 `ROOT_ITEM` → 递归遍历该 fs tree 的所有节点。本案 **28,278 个叶子、约 140 万条记录**（目标子卷全部文件，不止照片目录）。

这里读的是 LV 上**最后一次提交**的状态。卷仍挂载、但写入方已停，所以这棵树在读取期间基本不变；遇到个别读不通的节点会记录并跳过。

### 3. 孤儿叶子（`parse_leaves.py`）

`btrfs-find-root -a -o SUBVOL_ID` 能扫出属于该子卷的历史树块：本案 67 个 level-2、343 个 level-1、19,626 个 level-0。level-0 叶子是旧版本 fs tree 的残片，里面有**攻击前**的 `EXTENT_DATA` 记录。脚本逐个读取，校验块头里的 `bytenr`、`owner`、`level` 都对得上才解析。

### 4. 组装任务（`make_jobs2.py`）

参数 `CUTOFF` 是攻击开始时的 generation（本案第一封勒索信约 18141074，留余量实际用 18141060）。对每个现存 `.L0CK3D`：

1. **精确旧引用**（优先）：孤儿叶子里 `egen < CUTOFF` 的 `EXTENT_DATA`，同一 `foff` 取最新的那条。它就是攻击前「文件偏移 → extent 位置」的原样映射。
2. **整 extent 合成引用**：当前树（以及孤儿叶子）里 `egen < CUTOFF` 的每条引用，合成为 `(foff − eoff, disk_bytenr, 0, disk_num_bytes)`——即假设这个 extent 在攻击前是从 `foff − eoff` 开始、整块被这个文件使用。对「文件顺序写入、一个 extent 只属于一个文件」的照片和视频，这个假设成立；拼接后的文件头检查和抽样完整解码用来兜住它不成立的情况。

本案 24,142 个加密文件中 **17,696 个**至少有一条攻击前引用：`0x25` 7,197/7,197、`0x26` 10,209/10,220，`0x24` 只有 290/6,725。

### 5. 读回与拼接（`extract_jobs.py`）

对每个任务：

1. 读现存文件的页脚：原始大小、文件模式、pct；校验 `原始大小 + 588 == 文件大小`。
2. 按 soimy 的分段规则算出加密范围（`0x24` 全文件 / `0x26` 前 1 MiB / `0x25` 三段或五段）。
3. 读出现存文件的前 `原始大小` 字节作为底稿——加密范围外的字节本来就是明文。
4. 按 extent 列表顺序，**只填仍标记为「加密」的字节**：从 LV 读对应的旧字节；如果读回内容与现存密文完全相同（说明这块 extent 其实就是当前的密文，或者被原地覆盖了），**拒绝**，不标记为已恢复。
5. 全部加密字节都被填上且文件头可识别 → 写入 `OK/`；覆盖 ≥ 50% 且文件头可识别 → 缺口填零写入 `PARTIAL/`；否则 `FAIL`。
6. 输出用 `O_CREAT|O_EXCL` 新建在**另一个卷**上，绝不覆盖；被害卷只读。

超过 1.5 GiB 的文件（本案 32 个）会被标为 `BIG` 推迟处理，因为当前实现把整个文件读进内存；需要一个按段流式处理的版本（TODO）。

## 四、本案效果（中期）

| 指标 | 值 |
|---|---|
| 已处理 | 6,217 个文件 |
| 完整恢复 `OK` | **6,082 个，39.6 GiB**（全部文件头可识别） |
| 按模式 | `0x26` 4,918 / 4,920；`0x25` 1,108 完整 + 9 部分；`0x24` 56 / 177 |
| 部分恢复 `PARTIAL` | 9 个（均为 `0x25`，4.7 GiB） |
| 失败 `FAIL` | 123 个（121 个 `0x24`，2 个 `0x26`） |
| 推迟 `BIG` | 3 个（全量共 32 个） |
| 「读回 = 现存密文」被拒 | 0 次 |

早期只用孤儿叶子精确引用的版本（`make_jobs.py`），对前 600 个任务的完整恢复率约 82%；加入当前树的整 extent 合成后（`make_jobs2.py`），前 6,217 个任务的完整恢复率约 98%。两批文件不完全相同，这个对比只说明方向。

验证等级和局限见 [04](04-results-and-limits.md)。

## 五、辅助路径：旧 fs-tree 根 + `btrfs restore`

在写 bookend 工具之前，我们先用 btrfs-progs 自带的 `btrfs restore` 从旧树根恢复。要点：

1. **对底层 LV 运行**。DSM 挂载的是 `/dev/mapper/cachedev_N`，`btrfs restore` 对它报「is currently mounted」拒绝执行；它下面的 `/dev/mapper/vgN-volume_N` 内容相同、未被直接挂载，`btrfs restore` 只读它，输出写到另一卷。
2. **用 `-f` 直接指定 fs-tree 根**。本案旧 root tree 里指向目标子卷的指针所指块已被覆盖，`-t <旧 root tree> -r SUBVOL_ID` 恢复出 0 个文件。改为 `btrfs-find-root -a -o SUBVOL_ID` 找该子卷自己的历史根块，按 generation 挑勒索信之后、目标目录被加密之前的根，先 `-D` dry-run 看能列出多少文件。
3. 本案用 3 个约 14:55 的根（gen 18141107 / 18141129 / 18141132）：**2,442 个文件 / 19.9 GiB** 文件头校验通过；另有 1,075 个空文件、554 个内容已被覆盖（文件头无法识别）。

它的优点是现成工具、能拿到当时的完整目录结构；缺点是旧树块已部分被覆盖（大量 `parent transid verify failed`），只能恢复树还完整的那部分，且旧 extent 若已被释放复用就只能得到垃圾。它和 bookend 方法互补：bookend 擅长 `0x25`/`0x26`，旧树根可能补上一部分 `0x24`。两者结果的重叠尚未统计。

## 六、可以做得更好：用 btrfs 数据校验和做逐块验证

btrfs 默认为每 4 KiB 数据块保存 crc32c，存放在 csum tree，以磁盘逻辑地址为键。bookend 情况下 extent 仍处于分配状态，它的校验和**理论上仍完整保留在 csum tree 里**，包括已不被引用的那一段。因此可以：

1. 遍历 csum tree，取出被读回的每个 4 KiB 块的校验和；
2. 对读回的字节逐块计算 crc32c 并比对。

全部一致，就能说明读回的字节正是 btrfs 当初写下的原文——比文件头检查和图像解码强得多，对视频这类没法目视的文件尤其有用。前提是该共享文件夹开启了数据校验和（DSM 里「启用数据校验和」选项；关闭即 nodatasum，没有 csum）。本案**尚未做**这一步。
