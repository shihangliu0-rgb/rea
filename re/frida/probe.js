/*
 * re/frida/probe.js —— 用调用栈反推真实的限速调用链
 *
 * 为什么需要它：
 *   hooks.js 里 12 个点位中，只有 bucket.set_rate / bucket.consume 被调用了
 *   （实测 set_rate 208 次、consume 2665 次，其余 10 个全是 0 次）。
 *   说明那 10 个点位的地址虽然"字节签名对上了"，但**不在活的调用链上**。
 *
 *   这个脚本不猜地址：它只 hook 两个**已知活的**函数，然后记录
 *   `Thread.backtrace()` 拿到的调用者 RVA，按出现次数排序。
 *   谁在调用 set_rate(16384)，它的调用者就是真正的限速决策点。
 *
 * 用法：
 *   frida -p <baidunetdiskhost 的 pid> -l probe.js
 *   然后点一个下载，等 10~30 秒，在 REPL 里敲：
 *       report()
 *
 * 输出示例：
 *   ---------- 调用者排行 ----------
 *     set_rate 的调用者（共 208 次）：
 *       0x2e82bc  143 次  (68.8%)   ← 这是谁？顺着它往上找
 *       0xdd1e0    65 次  (31.3%)
 *     consume 的调用者（共 2665 次）：
 *       ...
 *
 * 注意：纯观察，不修改任何内存。
 */

var KERNEL = 'kernel.dll';

// 已知可用的两个点位（hooks.js 里实测被调用过）
var BASE_RVA = {
    'set_rate': 0xdd320,
    'consume': 0xdd340
};

// 如果要换版本，改这里（或让脚本自动按 SizeOfImage 选）
var TABLES = {
    0x2b25000: { 'set_rate': 0xdd320, 'consume': 0xdd340, 'vtable': 0x1259b24 },
    0x2a3a000: { 'set_rate': 0xdb150, 'consume': 0xdb170, 'vtable': 0x118cb44 }
};

// 签名校验（防止版本不对时 hook 到指令中间）
var SIGS = {
    'set_rate': '8b 44 24 04 85 c0',
    'consume': '53 57 56 89 ce'
};

// ── 统计容器 ───────────────────────────────────────────────────────────
var CALLERS = {};      // 'set_rate' -> { rvaString: count }
var RATE_HIST = {};    // 'set_rate' -> { value: count }   看下发过哪些速率
var SAMPLES = [];      // 原始调用栈样本（最多保留 40 条）
var MAX_SAMPLES = 40;
var TOTAL = {};

function log(m) { console.log(m); }

// ── 工具 ───────────────────────────────────────────────────────────────
function getModule(name) {
    try {
        if (Process.findModuleByName) return Process.findModuleByName(name);
        return Process.getModuleByName(name);
    } catch (e) {
        return null;
    }
}

function moduleOf(addr) {
    try {
        return Process.findModuleByAddress(addr);
    } catch (e) {
        return null;
    }
}

function fmtKey(k) { return k; }   // caller 已经是 '0x…' 形式，别再拼 0x

function fmt(addr) {
    var m = moduleOf(addr);
    if (!m) return addr.toString() + ' [非模块]';
    var rva = addr.sub(m.base);
    return m.name + '+0x' + hexNoPrefix(rva);
}

function hexNoPrefix(v) {
    // NativePointer.toString() 已经带 '0x'；toString(16) 在真机上不带。
    // 两者都兼容，避免拼出 '0x0x2e82bc'。
    var s = String(v).replace(/^0x/i, '');
    return s;
}

function rvaKey(addr) {
    var m = moduleOf(addr);
    if (!m) return null;
    if ((m.name || '').toLowerCase() !== KERNEL) return null;
    return '0x' + hexNoPrefix(addr.sub(m.base));
}

function bump2(bucket, key) {
    if (!bucket[key]) bucket[key] = 0;
    bucket[key]++;
}

// ── 核心：记录一次调用栈 ────────────────────────────────────────────────
function record(which, ctx, extra) {
    TOTAL[which] = (TOTAL[which] || 0) + 1;

    var frames;
    try {
        frames = Thread.backtrace(ctx, Backtracer.ACCURATE);
    } catch (e) {
        try { frames = Thread.backtrace(ctx, Backtracer.FUZZY); } catch (e2) { frames = []; }
    }

    // 第一个 kernel.dll 内的 frame 是 caller
    var caller = null;
    var chain = [];
    for (var i = 0; i < frames.length; i++) {
        var k = rvaKey(frames[i]);
        if (k) {
            if (caller === null) caller = k;
            chain.push(k);
            if (chain.length >= 4) break;
        }
    }

    if (caller) {
        if (!CALLERS[which]) CALLERS[which] = {};
        bump2(CALLERS[which], caller);
    }

    if (extra && extra.rate !== undefined) {
        if (!RATE_HIST[which]) RATE_HIST[which] = {};
        bump2(RATE_HIST[which], String(extra.rate));
    }

    if (SAMPLES.length < MAX_SAMPLES) {
        SAMPLES.push({
            which: which,
            caller: caller,
            chain: chain,
            extra: extra || {}
        });
    }

    if (!QUIET_RECORD) {
        log('[' + which + ']' + (extra && extra.rate !== undefined ?
            ' rate=' + extra.rate : '') +
            '  ← ' + (caller || '(无 kernel frame)') +
            (chain.length > 1 ? '  ⇐ ' + chain.slice(1).join(' ⇐ ') : ''));
    }
}

var QUIET_RECORD = false;   // true：只统计不刷屏（量大时很有用）

// ── 报告 ───────────────────────────────────────────────────────────────
function report() {
    log('');
    log('================ 调用者排行 ================');
    var names = Object.keys(TOTAL);
    if (!names.length) {
        log('  还没有任何命中。先在客户端里开始一个下载。');
        return;
    }
    for (var i = 0; i < names.length; i++) {
        var which = names[i];
        var total = TOTAL[which];
        log('');
        log('  ' + which + ' 共 ' + total + ' 次');

        // 速率分布
        var rh = RATE_HIST[which];
        if (rh) {
            var rk = Object.keys(rh).sort(function (a, b) { return rh[b] - rh[a]; });
            log('    下发的 rate 值：');
            for (var r = 0; r < Math.min(rk.length, 8); r++) {
                log('      ' + rk[r] + ' B/s  ×' + rh[rk[r]]);
            }
        }

        // 调用者
        var c = CALLERS[which];
        if (!c) { log('    （没有捕获到 kernel.dll 内的调用者）'); continue; }
        var keys = Object.keys(c).sort(function (a, b) { return c[b] - c[a]; });
        var sum = 0;
        for (var s = 0; s < keys.length; s++) sum += c[keys[s]];
        log('    调用者：');
        for (var j = 0; j < Math.min(keys.length, 10); j++) {
            var pct = (c[keys[j]] / sum * 100).toFixed(1);
            log('      ' + fmtKey(keys[j]) + '  ×' + c[keys[j]] + '  (' + pct + '%)');
        }
        if (keys.length > 10) log('      … 另有 ' + (keys.length - 10) + ' 个');
    }
    log('');
    log('===========================================');
    log('下一步：把上面占比最高的几个 RVA 发我，我去它们附近找真正的限速决策点。');
    log('        也可以直接敲  chains()  看完整调用链样本。');
}

// ── 完整调用链样本 ─────────────────────────────────────────────────────
function chains(n) {
    n = n || 15;
    log('');
    log('================ 调用链样本（最多 ' + n + ' 条）================');
    for (var i = 0; i < Math.min(SAMPLES.length, n); i++) {
        var s = SAMPLES[i];
        var extra = s.extra && s.extra.rate !== undefined ? ' rate=' + s.extra.rate : '';
        log('  #' + (i + 1) + ' [' + s.which + ']' + extra);
        log('      ' + (s.chain.length ? s.chain.join('  ⇐  ') : '(无 kernel frame)'));
    }
    if (!SAMPLES.length) log('  （暂无样本）');
    log('==============================================');
}

function reset() {
    CALLERS = {}; RATE_HIST = {}; SAMPLES = []; TOTAL = {};
    log('[i] 统计已清空');
}

globalThis.report = report;
globalThis.chains = chains;
globalThis.reset = reset;

// ── 安装 ───────────────────────────────────────────────────────────────
var mod = getModule(KERNEL);
if (!mod) {
    log('[!] 这个进程里没有 ' + KERNEL);
    log('    → 先跑 python census.py，attach 到 baidunetdiskhost.exe 的 pid');
} else {
    log('[i] ' + KERNEL + ' @ ' + mod.base + '  size=0x' + mod.size.toString(16));
    var table = TABLES[mod.size];
    if (!table) {
        log('[!] SizeOfImage=0x' + mod.size.toString(16) + ' 不在内置表里：' +
            Object.keys(TABLES).join(', '));
        log('    改 probe.js 顶部的 TABLES 即可。');
    } else {
        log('[i] 使用表：SizeOfImage=0x' + mod.size.toString(16));
        install(table);
    }
}

function bytesOk(addr, sig) {
    var want = sig.split(' ').join('').toLowerCase();
    var raw = addr.readByteArray(want.length / 2);
    var u8 = (raw instanceof ArrayBuffer) ? new Uint8Array(raw)
        : (raw.buffer ? new Uint8Array(raw.buffer) : new Uint8Array(raw));
    for (var i = 0; i < u8.length; i++) {
        var h = u8[i].toString(16);
        if (h.length < 2) h = '0' + h;
        if (h !== want.substr(i * 2, 2)) return false;
    }
    return true;
}

function install(table) {
    var ok = 0;

    // set_rate(uint32 rate)
    var a = mod.base.add(table['set_rate']);
    if (bytesOk(a, SIGS['set_rate'])) {
        Interceptor.attach(a, {
            onEnter: function (args) {
                var rate = -1;
                try { rate = args[0].toUInt32(); } catch (e) { }
                // 只记录较小的值（限速值通常 < 10 MiB/s），避免刷屏
                // 注意：TOTAL 的自增只在 record() 里做一次，这里不要再加，
                // 否则总次数会翻倍（曾导致 consume 10 次统计成 20 次）。
                record('set_rate', this.context,
                       (rate <= 0x1000000 && rate > 0) ? { rate: rate } : {});

            }
        });
        log('[+] hook set_rate @ ' + a + ' (RVA 0x' + table['set_rate'].toString(16) + ')');
        ok++;
    } else {
        log('[!] set_rate 字节不匹配，跳过');
    }

    // consume()  —— 只统计调用者，不打 rate
    var b = mod.base.add(table['consume']);
    if (bytesOk(b, SIGS['consume'])) {
        Interceptor.attach(b, {
            onEnter: function (args) {
                // 只在采样未满时抓栈（抓栈很贵，2665 次全抓会明显拖慢）
                if (SAMPLES.length < MAX_SAMPLES) {
                    record('consume', this.context, {});
                } else {
                    TOTAL['consume'] = (TOTAL['consume'] || 0) + 1;
                }
            }
        });
        log('[+] hook consume  @ ' + b + ' (RVA 0x' + table['consume'].toString(16) + ')');
        ok++;
    } else {
        log('[!] consume 字节不匹配，跳过');
    }

    log('========== probe 就绪：成功 ' + ok + ' 个 ==========');
    log('');
    log('现在去客户端里开始一个下载，等 10~30 秒，然后在 REPL 里敲：');
    log('    report()     看调用者排行（谁在调 set_rate、下了多大的 rate）');
    log('    chains()     看完整调用链样本');
    log('    QUIET_RECORD 设为 true 可以减少刷屏');
    log('');
}

// 首次报告提示
setTimeout(function () {
    if (Object.keys(TOTAL).length === 0) {
        log('[*] 还没命中。确认已经在下载（不是暂停状态）。');
    } else {
        log('[*] 已经有命中了，敲 report() 看结果');
    }
}, 15000);
