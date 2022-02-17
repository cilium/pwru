# Known Issues

This document outlines the known issues of pwru and workarounds.

## pwru killed by OOM when SELinux is enabled in some kernel versions

In some kernel versions, SELinux has a problem that it always generates the audit event (which later will be handled by auditd) per `bpf_probe_read_kernel` call. Since pwru calls it from hundreds or thousands of the BPF hook inside the kernel, a massive number of the audit events will be generated in a short time. As a result, the auditd cannot catch up to the speed and the message will be queued up to the backlog memory inside the kernel. Then, OOM killer works. When you are hitting this issue, you should see the `dmesg` like below.

```
[  232.680704] audit_log_start: 13274 callbacks suppressed
[  232.680706] audit: audit_backlog=65 > audit_backlog_limit=64
[  232.681686] audit: audit_lost=1228717 audit_rate_limit=0 audit_backlog_limit=64
[  232.682072] audit: backlog limit exceeded
[  232.682407] audit: audit_backlog=65 > audit_backlog_limit=64
[  232.682729] audit: audit_lost=1228718 audit_rate_limit=0 audit_backlog_limit=64
[  232.683095] audit: backlog limit exceeded
[  232.683442] audit: audit_backlog=65 > audit_backlog_limit=64
[  232.683769] audit: audit_lost=1228719 audit_rate_limit=0 audit_backlog_limit=64
[  232.684128] audit: backlog limit exceeded
[  232.684431] audit: audit_backlog=65 > audit_backlog_limit=64
[  236.816357] pwru invoked oom-killer: gfp_mask=0x100cca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0
[  236.816822] CPU: 0 PID: 2136 Comm: pwru Not tainted 5.11.12-300.fc34.x86_64 #1
[  236.817258] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
[  236.817737] Call Trace:
[  236.818110]  dump_stack+0x6b/0x83
[  236.818490]  dump_header+0x4a/0x1f3
[  236.818859]  oom_kill_process.cold+0xb/0x10
[  236.819240]  out_of_memory+0x229/0x4c0
[  236.819638]  __alloc_pages_slowpath.constprop.0+0xbf0/0xcc0
[  236.820054]  __alloc_pages_nodemask+0x30a/0x340
[  236.820443]  pagecache_get_page+0x192/0x470
[  236.820828]  filemap_fault+0x6bd/0xa50
[  236.821198]  ext4_filemap_fault+0x2d/0x40
[  236.821574]  __do_fault+0x36/0x100
[  236.821936]  handle_mm_fault+0x1174/0x1970
[  236.822309]  do_user_addr_fault+0x19f/0x480
[  236.822687]  exc_page_fault+0x67/0x150
[  236.823057]  ? asm_exc_page_fault+0x8/0x30
[  236.823440]  asm_exc_page_fault+0x1e/0x30
[  236.823814] RIP: 0033:0x42fbe0
[  236.824175] Code: Unable to access opcode bytes at RIP 0x42fbb6.
[  236.824589] RSP: 002b:000000c000041ec8 EFLAGS: 00010202
[  236.824996] RAX: 000000c000033400 RBX: 0000000000000017 RCX: 000000c000033400
[  236.825438] RDX: 0000000000000001 RSI: 0000000000000001 RDI: 0000003720f59a77
[  236.825882] RBP: 000000c000041ee0 R08: 00000000000008b2 R09: 0000000000000000
[  236.826329] R10: 0000000000000000 R11: 0000000000000246 R12: 000000c000041950
[  236.826782] R13: 000000c000032000 R14: 000000c0000004e0 R15: 00007ff583df5034
[  236.827278] Mem-Info:
[  236.827582] active_anon:224 inactive_anon:30787 isolated_anon:0
                active_file:351 inactive_file:227 isolated_file:0
                unevictable:0 dirty:3 writeback:0
                slab_reclaimable:4134 slab_unreclaimable:76903
                mapped:529 shmem:440 pagetables:803 bounce:0
                free:1921 free_pcp:25 free_cma:0
```

This issue was introduced in [this commit](https://github.com/torvalds/linux/commit/59438b46471ae6cdfb761afc8c9beaf1e428a331) (v5.6-rc1) and fixed in [this commit](https://github.com/torvalds/linux/commit/ff40e51043af63715ab413995ff46996ecf9583f) (v5.13-rc5) in the upstream kernel. So, any kernel using the revision between those two commits may be affected unless the fix is not backported.

To work around this issue, you can disable the SELinux or make it permissive mode, but we strongly encourage you to upgrade the kernel instead.
