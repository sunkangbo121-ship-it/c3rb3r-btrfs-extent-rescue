# 05 · 加固与收尾

本案的入侵路径没有完整还原（加密器和投放链在发现时已不在机器上），下面是根据现场暴露面和同一波事件的公开结论整理的清单。按顺序做，**恢复完成之前不要做会大量写被害卷的操作**。

## 处置期间引入的东西，先撤掉

- [ ] **删除临时 sudoers 片段**：`sudo rm /etc/sudoers.d/zz-ir-temp`，再 `sudo -l` 确认已无 NOPASSWD。
- [ ] 撤销为处置临时添加的 SSH 公钥；不再需要时关闭 SSH 服务。
- [ ] 停用的套件（相册、Drive、Cloud Sync、Download Station、Surveillance Station）在恢复完成并确认不再需要从该卷读旧 extent 之后再启动。相册重新索引会大量写盘。

## 关闭暴露面

- [ ] **关掉引导器的 telnet**。本案有 5 个 root `inetd` 来自黑群晖引导器带起来的 busybox，监听 `0.0.0.0:23`，开机即启动。检查方法：`sudo netstat -tlnp | grep ':23 '`、`ls -l /proc/*/exe 2>/dev/null | grep deleted`。处理方法因引导器而异：在引导器配置里关闭 telnet / 调试服务，或至少在防火墙上只允许本机访问。重启后再查一次。
- [ ] **WAN 不直接暴露 DSM 管理端口和 SSH**。关掉路由器上到 5000/5001/22/23 等端口的转发和 UPnP 自动映射，外网访问改走 VPN（WireGuard / OpenVPN / Tailscale 等）。
- [ ] DSM 防火墙：管理端口和 SSH 只允许局域网网段。
- [ ] 关闭不用的服务和套件（QuickConnect、WebDAV、FTP、Web Station 等），尤其是对外的。

## 打补丁

- [ ] 按群晖安全公告 **Synology-SA-26:13** 所列的修复版本升级 DSM 及相关套件。本案是黑群晖（DSM 7.2.1-69057 Update 1，引导器伪装 SA6400），升级前确认引导器支持目标版本，**先确保恢复数据已离开这台机器**再升级。
- [ ] 同一波事件中 soimy 的分析把入口高可信地指向 DSM 登录插件环境注入（与 CVE-2024-10441 一致），本案没有独立证据，但同样适用「先补丁、再开放」。

## 凭据

- [ ] **轮换所有凭据**：DSM 所有管理员与普通账号、SSH 密钥、套件内的账号（Cloud Sync 绑定的云盘授权、Download Station 的 RSS/PT 凭据、Surveillance Station 摄像头密码等）。Cloud Sync 自己的配置和数据库被加密过，视同已泄露，**到云盘服务端撤销授权**后重新绑定。
- [ ] 禁用 `admin` 账号，管理员开启双重验证。

## 持久化与复查

- [ ] **看 `/etc/cron.d` 的内容，不只看文件名**。lllong1377 的案例里持久化会伪装成正常名字并自我重建。本案目录 mtime 在攻击后（10/29 04:47），逐个看过内容是正常任务；复查时同样 `cat` 每个文件。
- [ ] 复查：`/etc/crontab`、`/etc/rc.local` 类启动脚本、`/usr/local/etc/rc.d/`、`/root/.ssh/authorized_keys`、各用户 `~/.ssh/authorized_keys`、`/etc/passwd` 中新增的 uid 0 账号、`systemctl list-units --type=service` 中陌生服务。
- [ ] 复查已知样本路径：`/bin/libgld`、`/bin/qnetd`（本案均不存在）。

## 数据

- [ ] **保留全部 `.L0CK3D` 原件**。将来如果出现针对 `0b5c8e4c` 会话的密钥或工具，`0x24` 小文件还有机会。原件可以移到离线介质，但不要删除、不要改写。
- [ ] 恢复出的文件放到独立介质，形成**离线或不可变**的备份（离线硬盘、不可变快照、异地备份），不要只依赖同一台 NAS 上的快照——攻击者拿到 root 后可以删快照。
- [ ] 开启共享文件夹的**数据校验和**（新建共享文件夹时可选）。它不防勒索，但能让以后的 extent 恢复做逐块验证（见 [03](03-btrfs-extent-retention.md)）。
- [ ] 为照片等不常改动的目录开启定时快照并设置保留策略；快照本身不防 root，但能挡住大量普通情况。
