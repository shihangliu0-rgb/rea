/*
 * re/frida/probe2.js —— 一次运行就把"限速到底卡在哪"问清楚
 *
 * 与 probe.js 的区别：
 *   probe.js 只统计 set_rate/consume 的**上一层调用者**；
 *   probe2.js 记录**完整调用链 + 线程 + 每个桶的速率**，并且能按速率反查
 *   （why(16384) → "谁把 16384 灌进来的"），输出一行可直接粘贴的摘要。
 *
 * 为什么需要它（实测结论）：
 *   242 版 12 个点位里，只有 bucket.set_rate / bucket.consume 真被调用。
 *   其中 set_rate 大部分调用是**构造期初始化**（push 0x80000 / 0x6400000 /
 *   0x1F400000 这些常量），真正把速率压到 16384 的是另一条路径。
 *   静态 xref 找不到它 —— 因为那条路径是**虚调用/函数指针**，只有运行时栈能看见。
 *
 * 用法：
 *   frida -p <baidunetdiskhost 的 pid> -l probe2.js
 *   点一个下载 → 10~30 秒后：
 *       report()        ← 总览 + 一行可粘贴摘要
 *       why(16384)      ← 只看"谁把速率设成 16384"的完整调用链
 *       buckets()       ← 有几个令牌桶、各自当前 rate/cap
 *       chains()        ← 原始调用链样本
 *       reset()
 *       boost()         ← 观察清楚后，再试强制提速（见下）
 *
 * 默认**纯观察，不改任何内存**。
 *
 * boost() 是唯一的写内存入口，它**不会重新 attach**（重新 attach 就是
 * 之前踩过的 e9 跳板坑，会让签名校验报 `实际=e9 ...`）。
 * 打开后：
 *   1. set_rate 的入参直接换成 0x1F400000（524288000 B/s，不限速哨兵）
 *   2. 每次 consume 之前，把桶的 rate(+0x20) 和 cap(+8) 再写一遍
 *      —— 这两个偏移是按 set_rate 的反汇编确定的：
 *         mov [ecx+0x20], eax        ← rate
 *         mov [ecx+8], max(eax,0x4000) ← cap
 *
 * ⚠ boost() 的效果**尚未在真机上验证过**。它只解决"桶里 rate=16384"这一层；
 *   如果瓶颈在"每 tick 只发 N 个请求"（consume 频率），boost 有效但速度仍受限，
 *   那时 report() 里能看到 consume 次数不变而 rate 已经很大 —— 这就是下一层。
 */

var KERNEL = 'kernel.dll';

// 版本表（按 SizeOfImage 自动选）
var TABLES = {
    0x2b25000: { 'set_rate': 0xdd320, 'consume': 0xdd340 },   // 3.0.20.242
    0x2a3a000: { 'set_rate': 0xdb150, 'consume': 0xdb170 }    // 3.0.20.237
};

/*
 * 限速器这一层（"谁在限制我"的真正决策者）。
 *
 * 怎么找到的：运行时调用链 + 静态反汇编互证。
 *   运行时 set_rate 的返回地址是 0x19fcf1 → 静态确认它是 0x19fcec 的 E8 调用点，
 *   所在函数 0x19fab0。这个函数：
 *       0x19fae2  cmp [edx+0xb4], 0      ← +0xb4 = 限流开关
 *       0x19fae9  je 0x19fce3
 *       0x19fce3  lea ecx,[edx+0x78]     ← 内嵌的 TokenBucket
 *       0x19fce6  push [edx+0xb0]        ← +0xb0 = 限速值（字节/秒）
 *       0x19fcec  call TokenBucket::set_rate
 *   它自己**没有任何 E8 调用者** → 是虚函数（只通过 vtable 调）。
 *   这解释了为什么之前"静态 xref 追不到上游"：只扫 E8 会漏掉虚调用。
 *
 * 同族的两个小方法（也是虚函数）：
 *   0x19fd30  mov [eax+0xb4],ecx ; test ecx,ecx ; je → 开关关闭时立刻把 +0xb0 下发
 *   0x19fd70  mov [ecx+0xb8],eax
 *
 * 注：+0xb0 在**整个文件里没有任何立即数写入**（16384/122880/1006860 一次都没有），
 *     所以它是运行时算出来的（服务端/配置 × 会员系数 × 限速比例）。
 */
var LIM = {
    0x2b25000: {                       // 3.0.20.242（已用样本公证）
        'apply': 0x19fab0,             // 虚函数：把速率下发给令牌桶
        'set_enabled': 0x19fd30,       // 虚函数：+0xb4 限流开关
        'set_x_b8': 0x19fd70           // 虚函数：+0xb8
    }
    // 0x2a3a000（237）暂缺：没有 237 样本，不猜地址（猜就是上一版翻车的原因）
};

var LIM_SIGS = {
    'apply': '55 89 e5 53 57 56 81 ec cc 00 00 00',
    'set_enabled': '89 c8 8b 4c 24 04 89 88 b4 00 00 00',
    'set_x_b8': '8b 44 24 04 89 81 b8 00 00 00 c2 04'
};

var SIGS = {
    'set_rate': '8b 44 24 04 85 c0',
    'consume': '53 57 56 89 ce'
};

var MAX_CHAIN = 10;        // 每次 backtrace 最多取几层
var MAX_SAMPLES = 60;      // 保留多少条原始样本
var MAX_RATES = 40;        // 速率直方图最多记多少个不同值
var CONSUME_BACKTRACE = 150; // consume 太多，只对前 N 次取栈

// ── 统计容器 ────────────────────────────────────────────────────────────
var S = {
    set_rate: { total: 0, byCaller: {}, byRate: {}, byThread: {}, samples: [],
                byCallerRate: {}, chains: {} },
    consume:  { total: 0, byCaller: {}, byThread: {}, samples: [], chains: {} }
};
var BUCKETS = {};          // '0x地址' -> { rate: n, cap: n, consume: n, set: n }

// 限速器层（0x19fab0 这一族）
var LIMITERS = {};         // '0x对象地址' -> { want, enabled, b8, gate, applies, callers{} }
var LIM_TOTAL = 0;         // apply 被调用次数
var LIM_FLAG_CALLS = [];   // set_enabled 的调用记录（谁在开关限流）
var BUCKET_TO_LIM = {};    // '0x桶' -> 限速器对象
var RATE_OVERFLOW = 0;     // 超过 MAX_RATES 的次数

// ── 强制提速开关（默认关）─────────────────────────────────────────────
var BOOST = false;
var BOOST_SENTINEL = 0x1F400000;   // 524288000 B/s = 500 MiB/s
var BOOST_STAT = { setRate: 0, bucketWrites: 0, limiters: 0, err: 0 };

function log(m) { console.log(m); }

// ── 工具 ────────────────────────────────────────────────────────────────
function getModule(name) {
    try {
        return Process.findModuleByName ? Process.findModuleByName(name)
                                        : Process.getModuleByName(name);
    } catch (e) { return null; }
}

function moduleOf(addr) {
    if (!addr) return null;
    try {
        if (Process.findModuleByAddress) return Process.findModuleByAddress(addr);
        return Process.getModuleByAddress(addr);
    } catch (e) { return null; }
}

// 统一格式化：真机上 NativePointer.toString() 已带 '0x'，toString(16) 不带
function hexNoPrefix(v) {
    return String(v).replace(/^0x/i, '');
}

/** 把任意地址变成 'kernel.dll+0x2e82bc' 或 'netbase.dll+0x1234' 或 '?? 0x...' */
function frameKey(addr) {
    if (!addr) return '??';
    var m = moduleOf(addr);
    if (!m) return '?? ' + String(addr);
    var rva = addr.sub(m.base);
    var nm = (m.name || '?');
    return nm + '+0x' + hexNoPrefix(rva);
}

/** 只要 kernel.dll 内的 RVA 字符串，其它模块原样返回模块名+偏移 */
function rvaKey(addr) {
    var k = frameKey(addr);
    // 'kernel.dll+0x2e82c7' → '0x2e82c7'（注意只切掉 "kernel.dll+"，保留 0x）
    if (k.indexOf(KERNEL + '+0x') === 0) return k.slice(KERNEL.length + 1);
    return k;
}

function pad(s, n) {
    s = String(s);
    while (s.length < n) s = ' ' + s;
    while (s.length > n) s = s.slice(0, n);
    return s;
}

function padR(s, n) {
    s = String(s);
    while (s.length < n) s = s + ' ';
    return s;
}

function bump(o, k) {
    o[k] = (o[k] || 0) + 1;
}

/** 按次数降序取前 n 项 */
function topN(obj, n) {
    var a = [];
    for (var k in obj) a.push([k, obj[k]]);
    a.sort(function (x, y) { return y[1] - x[1]; });
    return a.slice(0, n);
}

function pct(x, total) {
    if (!total) return '  0.0%';
    return pad((x * 100 / total).toFixed(1), 5) + '%';
}

/** 取调用栈（当前 context 起），返回 frameKey 数组 */
function stackHere(ctx, skipSelf) {
    var out = [];
    try {
        var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
        for (var i = 0; i < bt.length && out.length < MAX_CHAIN; i++) {
            var k = frameKey(bt[i]);
            if (skipSelf && k === skipSelf) continue;
            out.push(k);
        }
    } catch (e) { }
    return out;
}

/**
 * 取 __thiscall 的 this。
 * Frida 的 this.thisPtr 在老版本上可能为空，这里退回 context.ecx。
 * （hooks.js 在用户机器上 thisPtr 是可用的，两条路都留着。）
 */
function thisOf(ctx) {
    try {
        if (ctx.thisPtr && !ctx.thisPtr.isNull()) return ctx.thisPtr;
    } catch (e) { }
    try {
        var ecx = ctx.context && ctx.context.ecx;
        if (ecx && !ecx.isNull()) return ecx;
    } catch (e) { }
    return null;
}

function tid() {
    try {
        return Process.getCurrentThreadId();
    } catch (e) { return -1; }
}

// ── 版本探测 ────────────────────────────────────────────────────────────
var kb = getModule(KERNEL);
var RVA = null;
if (kb) {
    var sz = kb.size >>> 0;
    if (TABLES[sz]) {
        RVA = TABLES[sz];
        log('[+] kernel.dll 版本匹配：SizeOfImage=0x' + sz.toString(16) +
            (sz === 0x2b25000 ? '（3.0.20.242）' : '（3.0.20.237）'));
    } else {
        log('[!] 未知的 kernel.dll 版本：SizeOfImage=0x' + sz.toString(16));
        log('    已知：0x2b25000=242, 0x2a3a000=237。请把这一行发我。');
    }
} else {
    log('[!] 没找到 kernel.dll。请确认目标进程是 baidunetdiskhost.exe。');
}

/** 签名校验：防止版本不对时 hook 到指令中间 */
function bytesOk(addr, sig) {
    try {
        var want = sig.split(' ');
        var got = new Uint8Array(addr.readByteArray(want.length));
        for (var i = 0; i < want.length; i++) {
            if (got[i] !== parseInt(want[i], 16)) return false;
        }
        return true;
    } catch (e) { return false; }
}

// ── 挂 hook ─────────────────────────────────────────────────────────────
function attachAll() {
    if (!kb || !RVA) return false;

    var aRate = kb.base.add(RVA['set_rate']);
    var aConsume = kb.base.add(RVA['consume']);

    if (!bytesOk(aRate, SIGS['set_rate'])) {
        log('[!] set_rate 签名不匹配 @ ' + aRate + '，已放弃（防止挂错）');
    } else {
        Interceptor.attach(aRate, {
            onEnter: function (args) {
                var st = S.set_rate;
                st.total++;

                var self = KERNEL + '+0x' + hexNoPrefix(aRate.sub(kb.base));
                var caller = rvaKey(this.returnAddress);
                var rate = 0;
                try { rate = args[0].toUInt32(); } catch (e) { }

                // —— 强制提速：直接换掉入参（不重新 attach）——
                if (BOOST) {
                    try {
                        args[0] = ptr(BOOST_SENTINEL);
                        BOOST_STAT.setRate++;
                        rate = BOOST_SENTINEL;
                    } catch (e) {
                        BOOST_STAT.err++;
                        if (BOOST_STAT.err === 1) log('[!] 改 args[0] 失败: ' + e);
                    }
                }

                bump(st.byCaller, caller);
                var cr = st.byCallerRate[caller] || (st.byCallerRate[caller] = {});
                bump(cr, rate);
                bump(st.byThread, tid());

                // 速率直方图（超出上限的只累加溢出计数）
                if (st.byRate[rate] !== undefined) {
                    st.byRate[rate]++;
                } else if (Object.keys(st.byRate).length < MAX_RATES) {
                    st.byRate[rate] = 1;
                } else {
                    RATE_OVERFLOW++;
                }

                // 样本 + 调用链
                if (st.samples.length < MAX_SAMPLES) {
                    var chain = stackHere(this.context, self);
                    st.samples.push({ rate: rate, tid: tid(), caller: caller,
                                      chain: chain, when: Date.now() });
                    if (!st.chains[caller]) st.chains[caller] = chain;
                }

                // 记录桶（__thiscall：this 在 ecx）
                try {
                    var th = thisOf(this);
                    if (th && !th.isNull()) {
                        var key = String(th);
                        var b = BUCKETS[key] || (BUCKETS[key] = { rate: 0, cap: 0,
                                                                  consume: 0, set: 0,
                                                                  tokens: -1, empty: 0,
                                                                  replenish: 0, lastCall: 0 });
                        b.set++;
                        b.rate = rate;
                        b.cap = th.add(8).readU32();
                        b.lastCaller = caller;
                    }
                } catch (e) { }
            }
        });
        log('[+] hook set_rate @ ' + aRate + ' (kernel.dll+0x' + RVA['set_rate'].toString(16) + ')');
    }

    if (!bytesOk(aConsume, SIGS['consume'])) {
        log('[!] consume 签名不匹配 @ ' + aConsume + '，已放弃');
    } else {
        Interceptor.attach(aConsume, {
            onEnter: function () {
                var st = S.consume;
                st.total++;

                // 先读桶里的 rate（这才是"本 tick 用的速率"）
                var rate = -1, cap = -1;
                try {
                    var th = thisOf(this);
                    if (th && !th.isNull()) {
                        rate = th.add(0x20).readU32();
                        cap = th.add(8).readU32();
                        var key = String(th);
                        var b = BUCKETS[key] || (BUCKETS[key] = { rate: 0, cap: 0,
                                                                  consume: 0, set: 0,
                                                                  tokens: -1, empty: 0,
                                                                  replenish: 0, lastCall: 0 });
                        b.consume++;
                        b.rate = rate;
                        b.cap = cap;
                        // 令牌余额（64 位）：consume 里 `add eax,[esi+0x10]; adc edx,[esi+0x14]`
                        try {
                            b.tokens = th.add(0x10).readU32();
                            // 余额远小于 cap = 桶被抽干 = 这一刻在等令牌 → 限速生效中
                            if (b.tokens < b.cap / 2) b.empty++;
                            // 补充速率：距上次调用过了多久（毫秒），余额涨了多少
                            var now = Date.now();
                            if (b.lastCall && b.lastTokens !== undefined &&
                                now - b.lastCall > 20) {
                                var gain = b.tokens - b.lastTokens;
                                var dr = gain * 1000 / (now - b.lastCall);
                                if (dr > 0) b.replenish = Math.round(dr);
                            }
                            b.lastCall = now;
                            b.lastTokens = b.tokens;
                        } catch (e4) { }
                        // —— 强制提速：吐出去之前再写一遍（set_rate 只在瓶颈处生效一半）——
                        if (BOOST) {
                            try {
                                th.add(0x20).writeU32(BOOST_SENTINEL);
                                th.add(8).writeU32(BOOST_SENTINEL);
                                BOOST_STAT.bucketWrites++;
                                b.rate = BOOST_SENTINEL;
                                b.cap = BOOST_SENTINEL;
                            } catch (e2) {
                                BOOST_STAT.err++;
                            }
                        }
                    }
                } catch (e) { }

                if (st.total <= CONSUME_BACKTRACE) {
                    var self = KERNEL + '+0x' + hexNoPrefix(aConsume.sub(kb.base));
                    var caller = rvaKey(this.returnAddress);
                    bump(st.byCaller, caller);
                    bump(st.byThread, tid());
                    if (st.samples.length < MAX_SAMPLES) {
                        var chain = stackHere(this.context, self);
                        st.samples.push({ rate: rate, cap: cap, tid: tid(),
                                          caller: caller, chain: chain, when: Date.now() });
                        if (!st.chains[caller]) st.chains[caller] = chain;
                    }
                }
            }
        });
        log('[+] hook consume  @ ' + aConsume + ' (kernel.dll+0x' + RVA['consume'].toString(16) + ')');
    }

    // ── 限速器层（只有 242 有表）──
    var lim = LIM[sz];
    if (lim) {
        // 虚函数：把速率下发给令牌桶
        var aApply = kb.base.add(lim['apply']);
        if (!bytesOk(aApply, LIM_SIGS['apply'])) {
            log('[!] 限速器 apply 签名不匹配 @ ' + aApply + '，跳过');
        } else {
            Interceptor.attach(aApply, {
                onEnter: function () {
                    LIM_TOTAL++;
                    var self = thisOf(this);
                    if (!self || self.isNull()) return;
                    var key = String(self);
                    var L = LIMITERS[key] || (LIMITERS[key] = {
                        want: -1, enabled: -1, b8: -1, gate: 0, applies: 0, callers: {}
                    });
                    L.applies++;
                    try { L.b8 = self.add(0xb8).readU32(); } catch (e) { }
                    // —— 强制提速：直接把限速器的目标值也抬上去 ——
                    if (BOOST) {
                        try {
                            self.add(0xb0).writeU32(BOOST_SENTINEL);
                            BOOST_STAT.limiters = (BOOST_STAT.limiters || 0) + 1;
                        } catch (e3) { BOOST_STAT.err++; }
                    }
                    try {
                        // ⚠ +0xb4 是**有符号**的：-1 (4294967295) = 不限流
                        L.enabled = self.add(0xb4).readS32();
                        // +0xb0 一直读（开关关闭时它可能是旧值/0，这本身就是证据）
                        L.want = self.add(0xb0).readU32();
                        if (L.enabled !== 0) {
                            BUCKET_TO_LIM[String(self.add(0x78))] = key;
                        }
                    } catch (e) { }
                }
            });
            log('[+] hook 限速器 apply   @ ' + aApply +
                ' (kernel.dll+0x' + lim['apply'].toString(16) + ')');
        }

        // 限流开关被谁拨动
        var aEn = kb.base.add(lim['set_enabled']);
        if (!bytesOk(aEn, LIM_SIGS['set_enabled'])) {
            log('[!] 限速器 set_enabled 签名不匹配 @ ' + aEn + '，跳过');
        } else {
            Interceptor.attach(aEn, {
                onEnter: function (args) {
                    var self = thisOf(this);
                    if (!self || self.isNull()) return;
                    var key = String(self);
                    var L = LIMITERS[key] || (LIMITERS[key] = {
                        want: -1, enabled: -1, b8: -1, gate: 0, applies: 0, callers: {}
                    });
                    var on = 0;
                    try { on = args[0].toInt32(); } catch (e) { }
                    L.enabled = on;
                    if (LIM_FLAG_CALLS.length < 60) {
                        LIM_FLAG_CALLS.push({
                            when: Date.now(), on: on, obj: key,
                            caller: rvaKey(this.returnAddress),
                            chain: stackHere(this.context, KERNEL + '+0x' +
                                             hexNoPrefix(aEn.sub(kb.base)))
                        });
                    }
                }
            });
            log('[+] hook 限速开关   @ ' + aEn +
                ' (kernel.dll+0x' + lim['set_enabled'].toString(16) + ')');
        }

        // +0xb8 的写入点（虚函数，242 上就是 0x19fd70）
        var aB8 = kb.base.add(lim['set_x_b8']);
        if (!bytesOk(aB8, LIM_SIGS['set_x_b8'])) {
            log('[!] 限速器 set_x_b8 签名不匹配 @ ' + aB8 + '，跳过');
        } else {
            Interceptor.attach(aB8, {
                onEnter: function (args) {
                    var self = thisOf(this);
                    if (!self || self.isNull()) return;
                    var key = String(self);
                    var L = LIMITERS[key] || (LIMITERS[key] = {
                        want: -1, enabled: -1, b8: -1, gate: 0, applies: 0, callers: {}
                    });
                    var v = 0;
                    try { v = args[0].toUInt32(); } catch (e) { }
                    L.b8 = v;
                    // 语义还没确认（不猜），只记录谁写的、写了多少
                    var ck = rvaKey(this.returnAddress);
                    L.callers[ck] = (L.callers[ck] || 0) + 1;
                }
            });
            log('[+] hook set_x_b8     @ ' + aB8 +
                ' (kernel.dll+0x' + lim['set_x_b8'].toString(16) + ')');
        }
    } else {
        log('[i] 该版本没有限速器表（只有 242 有），跳过这一层');
    }

    log('');
    log('    现在去点一个下载，等 10~30 秒，然后敲：report()');
    log('');
    return true;
}

// ── 报告 ────────────────────────────────────────────────────────────────
function fmtRate(v) {
    if (v === 0x1F400000) return v + ' (哨兵=不限)';
    if (v === 0) return '0 (清零)';
    var s = '' + v;
    if (v >= 1048576) s += ' / ' + (v / 1048576).toFixed(2) + ' MiB/s';
    else s += ' / ' + (v / 1024).toFixed(1) + ' KiB/s';
    if (v === 0x4000) s += '   ← set_rate 的地板值，说明上游传了 ≤16384';
    return s;
}

function report() {
    log('');
    log('================ 限速链路总览 ================');
    log('  kernel.dll 基址 ' + kb.base + '   (' + KERNEL + ')');

    var sr = S.set_rate, cs = S.consume;
    if (!sr.total && !cs.total) {
        log('  还没有任何命中：确认点过下载，并且等待了几秒。');
        return;
    }
    log('  set_rate 共 ' + sr.total + ' 次，consume 共 ' + cs.total + ' 次');
    if (BOOST) {
        log('  [BOOST 打开] 已改写限速器 ' + (BOOST_STAT.limiters || 0) +
            ' 次，set_rate 入参 ' + BOOST_STAT.setRate +
            ' 次，重写桶 ' + BOOST_STAT.bucketWrites + ' 次' +
            (BOOST_STAT.err ? '，失败 ' + BOOST_STAT.err + ' 次' : ''));
    }
    log('  线程：' + Object.keys(sr.byThread).length + ' 个调用过 set_rate');

    // ── 1. 速率分布 ──
    log('');
    log('---------- 1. set_rate 下发的速率分布（谁在下发限速值）----------');
    var rates = topN(sr.byRate, 12);
    for (var i = 0; i < rates.length; i++) {
        log('  ' + padR(fmtRate(parseInt(rates[i][0], 10)), 62) +
            pad(rates[i][1], 5) + ' 次 ' + pct(rates[i][1], sr.total));
    }
    if (RATE_OVERFLOW) log('  （另有 ' + RATE_OVERFLOW + ' 次其它小值，未列出）');

    // ── 2. 调用者排行 ──
    log('');
    log('---------- 2. set_rate 的调用者排行 ----------');
    var callers = topN(sr.byCaller, 12);
    for (var j = 0; j < callers.length; j++) {
        log('  ' + padR(callers[j][0], 34) + pad(callers[j][1], 5) + ' 次 ' +
            pct(callers[j][1], sr.total));
    }

    // ── 3. 谁下发了 16384（重点）──
    var floorCallers = null;
    for (var k in sr.byCallerRate) {
        if (sr.byCallerRate[k][0x4000]) {
            floorCallers = floorCallers || [];
            floorCallers.push([k, sr.byCallerRate[k][0x4000], sr.byCallerRate[k]]);
        }
    }
    log('');
    log('---------- 3. 谁把速率设成 16384（地板值）----------');
    if (!floorCallers) {
        log('  没有 16384。当前最小速率在下面：');
        var minr = null;
        for (var r in sr.byRate) {
            var vv = parseInt(r, 10);
            if (vv > 0 && (minr === null || vv < minr)) minr = vv;
        }
        if (minr !== null) log('  最小 rate = ' + fmtRate(minr));
    } else {
        for (var f = 0; f < floorCallers.length; f++) {
            var c = floorCallers[f];
            log('  ' + padR(c[0], 34) + pad(c[1], 5) + ' 次');
            var others = topN(c[2], 5);
            var parts = [];
            for (var o = 0; o < others.length; o++) {
                parts.push(others[o][0] + '×' + others[o][1]);
            }
            log('      这个调用者下发过的全部速率：' + parts.join(', '));
            if (sr.chains[c[0]]) {
                log('      它的调用链：');
                var ch = sr.chains[c[0]];
                for (var q = 0; q < ch.length; q++) {
                    log('        ' + (q === 0 ? '← ' : '  ') + ch[q]);
                }
            }
        }
    }

    // ── 3.5 限速器真相（真正的决策者）──
    log('');
    log('---------- 3.5 限速器（0x19fab0 这一族）----------');
    var limKeys = Object.keys(LIMITERS);
    if (!LIM_TOTAL && !LIM_FLAG_CALLS.length) {
        log('  没有命中。可能：① 这个版本没挂这一层 ② 这次下载没走这条路');
    } else {
        log('  apply 共被调用 ' + LIM_TOTAL + ' 次，涉及 ' + limKeys.length + ' 个限速器对象');
        var limOn = 0, limOff = 0;
        var rows = [];
        for (var lk in LIMITERS) {
            var L = LIMITERS[lk];
            if (L.enabled === 1) limOn++; else if (L.enabled === 0) limOff++;
            rows.push([lk, L]);
        }
        rows.sort(function (x, y) { return y[1].applies - x[1].applies; });
        log('  开关状态：开 ' + limOn + ' 个 / 关 ' + limOff + ' 个');
        for (var rr = 0; rr < rows.length && rr < 10; rr++) {
            var o = rows[rr][1];
            log('  ' + rows[rr][0] + '  限流值(+0xb0)=' + padR(o.want, 11) +
                ' 开关(+0xb4)=' + padR(o.enabled, 3) +
                ' +0xb8=' + padR(o.b8, 8) + ' apply=' + o.applies);
            if (o.want > 0 && o.want < 0x4000) {
                log('      ⚠ 这个值 < 0x4000，令牌桶会把它抬到 16384 地板');
            }
        }
        if (LIM_FLAG_CALLS.length) {
            log('');
            log('  限流开关被拨动的记录（前 ' + LIM_FLAG_CALLS.length + ' 次）：');
            for (var fc = 0; fc < LIM_FLAG_CALLS.length && fc < 6; fc++) {
                var C = LIM_FLAG_CALLS[fc];
                log('    开关=' + C.on + '  对象=' + C.obj + '  调用者=' + C.caller);
                if (C.chain.length) {
                    log('      链: ' + C.chain.slice(0, 5).join(' → '));
                }
            }
        }
        // ── 结论判读（第一版这里读错了：-1 是"不限"，不是"关闭"）──
        var floored = 0, bigOpen = 0;
        for (var bk2 in BUCKETS) {
            var bb2 = BUCKETS[bk2];
            if (bb2.rate === 0x4000) floored++;
            if (bb2.rate >= 0x4000000) bigOpen++;
        }
        log('');
        var unlimited = 0, limited = 0;
        for (var lk2 in LIMITERS) {
            if (LIMITERS[lk2].enabled === -1) unlimited++;
            else if (LIMITERS[lk2].enabled !== 0) limited++;
        }
        log('  判读：' + unlimited + ' 个限速器 = -1（不限流），' +
            limited + ' 个真在限流；桶里 ' + bigOpen + ' 个已是大速率，' +
            floored + ' 个还在地板。');

        if (floored && floored === Object.keys(BUCKETS).length) {
            log('  ⚠ 全部桶都在地板 → 没有任何桶被下发过速率（构造默认值）。');
        } else if (floored) {
            log('  ⚠ 有 ' + floored + ' 个桶停在 16384 地板，而限速器给的是 -1/大值。');
            log('    说明这 16384 **不是限速器下发的** → 是那些桶的**构造默认值**，');
            log('    也就是"这一路没有被设过速率"。它们 consume 次数跟旁边的大桶一样多，');
            log('    所以它们不是瓶颈，是"配额未启用"的伴随桶。');
        }
        if (bigOpen && !limited) {
            log('  ⚠ 限速器全部 -1 且桶速已经很大 → 令牌桶这一层**已经不限制你了**。');
            log('    如果速度还是上不去，瓶颈在别处（见第 5 节）。');
        }
    }

    // ── 4. 令牌桶 ──
    var bk = [];
    for (var b in BUCKETS) bk.push([b, BUCKETS[b]]);
    bk.sort(function (x, y) { return y[1].consume - x[1].consume; });
    log('');
    log('---------- 4. 令牌桶（共 ' + bk.length + ' 个，按 consume 次数排）----------');
    for (var t = 0; t < bk.length && t < 10; t++) {
        var bb = bk[t][1];
        log('  ' + bk[t][0] + '  rate=' + padR(bb.rate, 10) + ' cap=' + padR(bb.cap, 10) +
            ' n=' + pad(bb.consume, 6) +
            ' 余额=' + pad(bb.tokens === undefined ? -1 : bb.tokens, 10) +
            ' 抽干=' + pad(bb.empty || 0, 6) +
            ' 实测补充=' + padR(bb.replenish || 0, 10) +
            (bb.lastCaller ? ' set来自 ' + bb.lastCaller : ''));
    }

    // ── 4.5 黑洞检测：令牌去哪了 ──
    log('');
    log('---------- 4.5 黑洞检测：令牌被谁吃掉了 ----------');
    var consumed = 0, drained = 0, bottleneck = null;
    for (var hb in BUCKETS) {
        var H = BUCKETS[hb];
        consumed += H.consume;
        if (H.empty) drained += H.empty;
        // 抽干比例高 = 这个桶一直在"等令牌" = 它才是在限制你
        var ratio = H.consume ? (H.empty / H.consume) : 0;
        if (H.consume >= 30 && ratio > 0.5 &&
            (!bottleneck || ratio > bottleneck.ratio)) {
            bottleneck = { addr: hb, b: H, ratio: ratio };
        }
    }
    log('  全进程令牌桶 consume 合计 ' + consumed + ' 次，其中 ' + drained +
        ' 次发生在"余额 < cap/2"（即桶被抽干）');
    if (bottleneck) {
        log('  ⚠ 最像瓶颈的桶：' + bottleneck.addr +
            '  rate=' + bottleneck.b.rate + ' cap=' + bottleneck.b.cap +
            '  抽干率=' + (bottleneck.ratio * 100).toFixed(0) + '%' +
            '  (' + bottleneck.b.empty + '/' + bottleneck.b.consume + ')');
        log('    实测令牌补充速率 ' + (bottleneck.b.replenish || 0) + ' B/s' +
            '（rate 字段写的是 ' + bottleneck.b.rate + '）');
        if ((bottleneck.b.replenish || 0) > 0 &&
            bottleneck.b.rate >= 0x4000000 &&
            bottleneck.b.replenish < bottleneck.b.rate / 10) {
            log('    ⚠ 令牌补充远低于 rate 字段 → **补充速率被别处压住了**。');
            log('      rate 只是个标称值，真正卡人的是补充函数（consume 里的 call 0x100d17d0）。');
        }
    } else {
        log('  没有桶的抽干率超过 50% → 令牌桶不是你现在的瓶颈。');
    }
    // 全部桶的抽干率排行
    var rank = [];
    for (var rb in BUCKETS) {
        var R = BUCKETS[rb];
        if (R.consume >= 30) rank.push([rb, R, R.empty / R.consume]);
    }
    rank.sort(function (x, y) { return y[2] - x[2]; });
    if (rank.length) {
        log('  抽干率排行（consume≥30 的桶）：');
        for (var rk = 0; rk < rank.length && rk < 6; rk++) {
            log('    ' + rank[rk][0] + '  ' + (rank[rk][2] * 100).toFixed(0) + '%' +
                '  (' + rank[rk][1].empty + '/' + rank[rk][1].consume + ')' +
                '  rate=' + rank[rk][1].rate +
                '  实测补充=' + (rank[rk][1].replenish || 0));
        }
    }

    // ── 5. 可粘贴摘要 ──
    log('');
    log('---------- 5. 把下面几行整段发我（不用截图）----------');
    var line1 = [], line2 = [];
    for (var p = 0; p < callers.length; p++) {
        line1.push(callers[p][0] + '=' + callers[p][1]);
    }
    for (var p2 = 0; p2 < rates.length; p2++) {
        line2.push(rates[p2][0] + 'x' + rates[p2][1]);
    }
    log('  set_rate callers: ' + line1.join(', '));
    log('  set_rate rates  : ' + line2.join(', '));
    log('  consume callers : ' + topN(cs.byCaller, 8).map(function (x) {
        return x[0] + '=' + x[1];
    }).join(', '));
    log('  buckets         : ' + bk.slice(0, 6).map(function (x) {
        return x[0] + '(rate=' + x[1].rate + ',n=' + x[1].consume +
               ',dup=' + (x[1].empty || 0) + ',refill=' + (x[1].replenish || 0) + ')';
    }).join(' '));
    log('  limiter         : ' + (function () {
        var a = [];
        for (var q2 in LIMITERS) {
            var Q = LIMITERS[q2];
            a.push(q2 + '(b0=' + Q.want + ',b4=' + Q.enabled + ',n=' + Q.applies + ')');
        }
        return a.length ? a.slice(0, 4).join(' ') : '-';
    })());
    log('=============================================');
    log('');
}

/** 只看某个速率是谁下发的，含完整调用链 */
function why(rate) {
    rate = (rate === undefined) ? 0x4000 : rate;
    var st = S.set_rate;
    var hit = 0;
    log('');
    log('=== 谁下发了 rate=' + rate + ' ===');
    var seen = {};
    for (var i = 0; i < st.samples.length; i++) {
        var s = st.samples[i];
        if (s.rate !== rate) continue;
        hit++;
        var sig = s.chain.join('>');
        if (seen[sig]) { seen[sig].n++; continue; }
        seen[sig] = { n: 1, tid: s.tid, caller: s.caller, chain: s.chain };
    }
    if (!hit) {
        log('  样本里没有这个速率（样本只保留前 ' + MAX_SAMPLES + ' 次 set_rate）。');
        log('  先敲 reset() 再点下载，或者直接看 report() 的速率分布。');
        return;
    }
    var keys = Object.keys(seen);
    log('  采样到 ' + hit + ' 次，共 ' + keys.length + ' 种不同调用链：');
    for (var k = 0; k < keys.length; k++) {
        var e = seen[keys[k]];
        log('  [' + (k + 1) + '] ' + e.n + ' 次，线程 ' + e.tid + '，直接调用者 ' + e.caller);
        for (var q = 0; q < e.chain.length; q++) {
            log('        ' + padR('#' + q, 4) + e.chain[q]);
        }
    }
    log('');
}

/** 原始样本：每条一行，看时序 */
function chains(n) {
    n = n || 20;
    log('');
    log('=== 调用链样本（最近 ' + n + ' 条）===');
    var all = S.set_rate.samples.concat(S.consume.samples);
    all.sort(function (a, b) { return a.when - b.when; });
    var start = Math.max(0, all.length - n);
    for (var i = start; i < all.length; i++) {
        var s = all[i];
        var kind = (s.cap === undefined) ? 'set_rate' : 'consume ';
        log('  ' + kind + ' rate=' + padR(s.rate, 12) + ' tid=' + padR(s.tid, 5) +
            ' caller=' + padR(s.caller, 30));
        for (var q = 0; q < s.chain.length && q < 6; q++) {
            log('        ' + padR('#' + q, 4) + s.chain[q]);
        }
    }
    if (!all.length) log('  （没有样本）');
    log('');
}

/** 单独看桶 */
function buckets() {
    log('');
    log('=== 令牌桶 ===');
    var any = false;
    for (var b in BUCKETS) {
        any = true;
        var x = BUCKETS[b];
        log('  ' + b + '  rate=' + x.rate + ' cap=' + x.cap +
            ' set=' + x.set + ' consume=' + x.consume);
    }
    if (!any) log('  （还没有记录到桶）');
    log('');
}

/**
 * 强制提速。
 *   boost()      → 打开（并打印当前状态）
 *   boost(false) → 关闭
 * 不会重新 attach，所以不会触发 e9 跳板问题。
 */
function boost(on) {
    if (on === undefined) on = !BOOST;
    BOOST = !!on;
    log('');
    if (BOOST) {
        log('[!] BOOST 已打开：');
        log('    ① 限速器的 +0xb0（限流值）直接写成 0x1F400000');
        log('    ② set_rate 入参 → 0x1F400000 (524288000 B/s)');
        log('    ③ 每次 consume 前把桶的 +0x20(rate) / +8(cap) 重写一遍');
        log('    ⚠ 这一层尚未在真机验证。打开后重新点下载，再看速度；');
        log('      30 秒后敲 report() —— 如果 rate 已经很大但 consume 次数不变，');
        log('      说明瓶颈在"每 tick 请求数"，不在令牌桶。');
        log('    关闭：boost(false)');
    } else {
        log('[+] BOOST 已关闭（恢复纯观察）');
    }
    log('');
    return BOOST;
}

function reset() {
    S = {
        set_rate: { total: 0, byCaller: {}, byRate: {}, byThread: {}, samples: [],
                    byCallerRate: {}, chains: {} },
        consume:  { total: 0, byCaller: {}, byThread: {}, samples: [], chains: {} }
    };
    BUCKETS = {};
    LIMITERS = {};
    LIM_TOTAL = 0;
    LIM_FLAG_CALLS = [];
    BUCKET_TO_LIM = {};
    RATE_OVERFLOW = 0;
    log('[+] 已清零');
}

attachAll();
