/*
 * re/frida/throughput.js —— 实测吞吐：数据到底有没有进来
 *
 * 为什么需要它：
 *   boost() 已经把 token bucket 这一层全部放开（set_rate 入参 71.5% 变成
 *   524288000、主桶 rate 122880→524288000、consume 553→1853），但下载速度不变。
 *   所以必须回答一个问题：**是"没有配额"，还是"没有数据"？**
 *
 *   这个脚本不去猜任何 RVA，只挂**导出函数**：
 *     ws2_32!WSARecv / WSARecvFrom / WSASend / WSASendTo   请求字节 + 同步完成字节
 *     ws2_32!WSAGetOverlappedResult                        异步(overlapped)完成字节
 *     kernel32!GetQueuedCompletionStatus                   IOCP 完成字节（最准的总量）
 *     kernel32!ReadFile                                   兜底：走文件/管道的情况
 *   再可选挂 kernel.dll 的 set_rate / consume 做对照。
 *
 * 用法：
 *   frida -p <baidunetdiskhost 的 pid> -l throughput.js
 *   点一个下载 → 等 20~40 秒 →
 *       report()        ← 吞吐对照表 + 结论
 *       timeline()      ← 每个采样窗口一行的明细
 *       stop()          ← 停掉定时器（脚本仍可 report）
 *       start()         ← 重新开始
 *       live()          ← 实时滚屏（默认关）
 *       reset()
 *
 * 纯观察，不写任何内存。
 */

// ── 可调参数 ────────────────────────────────────────────────────────────
var INTERVAL_MS = 2000;   // 采样窗口
var MAX_WINDOWS = 120;    // 最多保留多少个窗口

var WS2 = 'ws2_32.dll';
var K32 = 'kernel32.dll';
var KERNEL = 'kernel.dll';

// kernel.dll 上的对照点（有表才挂，没有就跳过，不猜地址）
var TABLES = {
    0x2b25000: { 'set_rate': 0xdd320, 'consume': 0xdd340 },   // 3.0.20.242
    0x2a3a000: { 'set_rate': 0xdb150, 'consume': 0xdb170 }    // 3.0.20.237
};

var WSA_IO_PENDING = 997;

// ── 累计计数器（只增不减；report 用窗口快照做差）────────────────────────
var CUM = {
    // ws2 层
    recvReq: 0,        // WSARecv 请求的缓冲字节（= 客户端愿意收多少）
    recvDone: 0,       // WSARecv 同步完成的字节
    recvPending: 0,    // WSARecv 返回 WSA_IO_PENDING 的次数
    sendReq: 0,
    sendDone: 0,
    sendPending: 0,
    // 完成通知层
    ovDone: 0,         // WSAGetOverlappedResult 给出的字节
    iocpDone: 0,       // GetQueuedCompletionStatus 给出的字节（最接近"真实吞吐"）
    iocpCalls: 0,
    readDone: 0,       // ReadFile 完成的字节
    readCalls: 0,
    // kernel.dll 对照
    setRate: 0,
    consume: 0,
    rateSum: 0,        // 用来算平均下发速率
    lastRate: -1
};

var WINDOWS = [];      // [{t, d:{...}}]
var LAST = null;       // 上一次采样的 CUM 快照
var START_TS = 0;
var TIMER = null;
var LIVE = false;
var HOOKED = [];

function log(m) { console.log(m); }

// ── Frida 兼容层（17 删了静态 Module.*）────────────────────────────────
function getModule(name) {
    try {
        return Process.findModuleByName ? Process.findModuleByName(name)
                                        : Process.getModuleByName(name);
    } catch (e) { return null; }
}

function findExport(modName, sym) {
    var m = getModule(modName);
    if (m) {
        try {
            if (m.findExportByName) {
                var a = m.findExportByName(sym);
                if (a) return a;
            }
        } catch (e) { }
    }
    try {
        if (typeof Module !== 'undefined' && Module.findGlobalExportByName) {
            return Module.findGlobalExportByName(sym);
        }
    } catch (e) { }
    try {
        if (Module.findExportByName) return Module.findExportByName(null, sym);
    } catch (e) { }
    return null;
}

function pad(s, n) {
    s = String(s);
    while (s.length < n) s = ' ' + s;
    return s;
}
function padR(s, n) {
    s = String(s);
    while (s.length < n) s = s + ' ';
    return s;
}

/** 把 B/s 变成好读的字符串 */
function rate(v) {
    v = Math.round(v);
    if (v >= 1048576) return (v / 1048576).toFixed(2) + ' MiB/s';
    if (v >= 1024) return (v / 1024).toFixed(1) + ' KiB/s';
    return v + ' B/s';
}

/** 读 WSABUF 数组：WSABUF { ULONG len; char *buf; } = 8 字节 */
function sumWsabuf(arrPtr, count) {
    var total = 0;
    try {
        var n = count > 16 ? 16 : count;
        for (var i = 0; i < n; i++) {
            total += arrPtr.add(i * 8).readU32();
        }
    } catch (e) { }
    return total;
}

function safeU32(p) {
    if (!p) return 0;
    try {
        if (p.isNull && p.isNull()) return 0;
        return p.readU32();
    } catch (e) { return 0; }
}

// ── 挂 ws2_32 收发 ─────────────────────────────────────────────────────
function hookRecv(name, isUdp) {
    var addr = findExport(WS2, name);
    if (!addr) { log('[!] 没找到 ' + WS2 + '!' + name + '，跳过'); return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // WSARecv(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD nRecvd,
                //         LPDWORD flags, LPWSAOVERLAPPED ov, LPOVERLAPPED_COMPLETION_ROUTINE fn)
                this.nPtr = args[3];
                this.req = 0;
                try { this.req = sumWsabuf(args[1], args[2].toUInt32()); } catch (e) { }
                CUM.recvReq += this.req;
            },
            onLeave: function (retval) {
                var r = 0;
                try { r = retval.toInt32(); } catch (e) { }
                if (r === WSA_IO_PENDING) { CUM.recvPending++; return; }
                if (r === 0) {
                    var n = safeU32(this.nPtr);
                    if (n) CUM.recvDone += n;
                }
            }
        });
        HOOKED.push(name);
    } catch (e) { log('[!] 挂 ' + name + ' 失败: ' + e); }
}

function hookSend(name) {
    var addr = findExport(WS2, name);
    if (!addr) { log('[!] 没找到 ' + WS2 + '!' + name + '，跳过'); return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // WSASend(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD nSent,
                //         DWORD flags, LPWSAOVERLAPPED ov, ...)
                this.nPtr = args[3];
                this.req = 0;
                try { this.req = sumWsabuf(args[1], args[2].toUInt32()); } catch (e) { }
                CUM.sendReq += this.req;
            },
            onLeave: function (retval) {
                var r = 0;
                try { r = retval.toInt32(); } catch (e) { }
                if (r === WSA_IO_PENDING) { CUM.sendPending++; return; }
                if (r === 0) {
                    var n = safeU32(this.nPtr);
                    if (n) CUM.sendDone += n;
                }
            }
        });
        HOOKED.push(name);
    } catch (e) { log('[!] 挂 ' + name + ' 失败: ' + e); }
}

// ── 挂完成通知（这一步才是"真实吞吐"）──────────────────────────────────
function hookOverlappedResult() {
    var addr = findExport(WS2, 'WSAGetOverlappedResult');
    if (!addr) { log('[!] 没找到 WSAGetOverlappedResult，跳过'); return; }
    try {
        Interceptor.attach(addr, {
            // BOOL WSAGetOverlappedResult(SOCKET, LPWSAOVERLAPPED, LPDWORD lpcbTransfer, BOOL, LPDWORD)
            onEnter: function (args) { this.cbPtr = args[2]; },
            onLeave: function (retval) {
                var ok = 0;
                try { ok = retval.toInt32(); } catch (e) { }
                if (ok) CUM.ovDone += safeU32(this.cbPtr);
            }
        });
        HOOKED.push('WSAGetOverlappedResult');
    } catch (e) { log('[!] 挂 WSAGetOverlappedResult 失败: ' + e); }
}

function hookIocp() {
    var addr = findExport(K32, 'GetQueuedCompletionStatus');
    if (!addr) { log('[!] 没找到 GetQueuedCompletionStatus，跳过'); return; }
    try {
        Interceptor.attach(addr, {
            // BOOL GetQueuedCompletionStatus(HANDLE port, LPDWORD pBytes, PULONG_PTR pKey,
            //                                LPOVERLAPPED *pOv, DWORD ms)
            onEnter: function (args) { this.nPtr = args[1]; },
            onLeave: function (retval) {
                CUM.iocpCalls++;
                var ok = 0;
                try { ok = retval.toInt32(); } catch (e) { }
                if (ok) CUM.iocpDone += safeU32(this.nPtr);
            }
        });
        HOOKED.push('GetQueuedCompletionStatus');
    } catch (e) { log('[!] 挂 IOCP 失败: ' + e); }
}

function hookReadFile() {
    var addr = findExport(K32, 'ReadFile');
    if (!addr) return;
    try {
        Interceptor.attach(addr, {
            // BOOL ReadFile(HANDLE, LPVOID, DWORD nBytes, LPDWORD lpRead, LPOVERLAPPED)
            onEnter: function (args) { this.nPtr = args[3]; this.ov = args[4]; },
            onLeave: function (retval) {
                CUM.readCalls++;
                var ok = 0;
                try { ok = retval.toInt32(); } catch (e) { }
                // 异步 ReadFile：返回 FALSE + ERROR_IO_PENDING，字节数稍后由 IOCP 给
                if (ok) CUM.readDone += safeU32(this.nPtr);
            }
        });
        HOOKED.push('ReadFile');
    } catch (e) { }
}

// ── kernel.dll 对照 ────────────────────────────────────────────────────
function hookKernel() {
    var kb = getModule(KERNEL);
    if (!kb) { log('[i] 没找到 kernel.dll，只做 ws2/IOCP 观测'); return; }
    var sz = kb.size >>> 0;
    var t = TABLES[sz];
    if (!t) {
        log('[i] kernel.dll SizeOfImage=0x' + sz.toString(16) + ' 不在表里，跳过对照');
        return;
    }
    try {
        Interceptor.attach(kb.base.add(t['set_rate']), {
            onEnter: function (args) {
                CUM.setRate++;
                try {
                    var v = args[0].toUInt32();
                    CUM.rateSum += v;
                    CUM.lastRate = v;
                } catch (e) { }
            }
        });
        Interceptor.attach(kb.base.add(t['consume']), {
            onEnter: function () { CUM.consume++; }
        });
        HOOKED.push('kernel!set_rate', 'kernel!consume');
    } catch (e) { log('[!] 挂 kernel.dll 失败: ' + e); }
}

// ── 采样 ────────────────────────────────────────────────────────────────
function snapshot() {
    var o = {};
    for (var k in CUM) o[k] = CUM[k];
    return o;
}

function sample() {
    var now = Date.now();
    if (!LAST) { LAST = snapshot(); START_TS = now; return; }
    var cur = snapshot();
    var d = {};
    for (var k in cur) d[k] = cur[k] - LAST[k];
    var dt = (now - (WINDOWS.length ? WINDOWS[WINDOWS.length - 1].ts : START_TS)) / 1000;
    if (dt <= 0) dt = INTERVAL_MS / 1000;
    WINDOWS.push({ ts: now, dt: dt, d: d });
    if (WINDOWS.length > MAX_WINDOWS) WINDOWS.shift();
    LAST = cur;

    if (LIVE) {
        log('  [' + (dt).toFixed(1) + 's] ' +
            '收(完成) ' + padR(rate(d.recvDone / dt), 11) +
            ' IOCP ' + padR(rate(d.iocpDone / dt), 11) +
            ' 收(请求) ' + padR(rate(d.recvReq / dt), 11) +
            ' 发 ' + padR(rate(d.sendDone / dt), 11) +
            ' consume ' + d.consume);
    }
}

var RUNNING = false;

function start() {
    if (RUNNING) { log('[i] 定时器已经在跑'); return; }
    LAST = snapshot();          // 立刻建基线，第一个窗口就是有效数据
    START_TS = Date.now();
    RUNNING = true;
    TIMER = setInterval(function () {
        try { sample(); } catch (e) { log('[!] 采样出错: ' + e); }
    }, INTERVAL_MS);
    log('[+] 开始采样，窗口 ' + INTERVAL_MS + ' ms');
}

function stop() {
    if (RUNNING) {
        try { clearInterval(TIMER); } catch (e) { }
        TIMER = null;
        RUNNING = false;
        log('[+] 已停止采样（数据还在，可以 report()）');
    } else {
        log('[i] 定时器没在跑');
    }
}

function live(on) {
    LIVE = (on === undefined) ? !LIVE : !!on;
    log('[+] 实时滚屏 ' + (LIVE ? '开' : '关'));
    return LIVE;
}

function reset() {
    for (var k in CUM) CUM[k] = 0;
    WINDOWS = [];
    LAST = null;
    START_TS = Date.now();
    log('[+] 已清零');
}

// ── 报告 ────────────────────────────────────────────────────────────────
function avg(key, unit) {
    var sum = 0, t = 0;
    for (var i = 0; i < WINDOWS.length; i++) {
        sum += WINDOWS[i].d[key];
        t += WINDOWS[i].dt;
    }
    if (!t) return 0;
    return unit ? sum / t : sum;
}

function peak(key) {
    var best = 0;
    for (var i = 0; i < WINDOWS.length; i++) {
        var v = WINDOWS[i].d[key] / WINDOWS[i].dt;
        if (v > best) best = v;
    }
    return best;
}

function total(key) {
    var s = 0;
    for (var i = 0; i < WINDOWS.length; i++) s += WINDOWS[i].d[key];
    return s;
}

function report() {
    log('');
    log('================ 吞吐对照 ================');
    if (!WINDOWS.length) {
        log('  还没有采样窗口。先点下载，等 10 秒以上。');
        if (!RUNNING) log('  （定时器没在跑 → 敲 start()）');
        return;
    }
    var span = 0;
    for (var i = 0; i < WINDOWS.length; i++) span += WINDOWS[i].dt;

    log('  窗口 ' + WINDOWS.length + ' 个，共 ' + span.toFixed(1) + ' 秒（每窗 ' +
        INTERVAL_MS + ' ms）');
    log('  已挂上的点：' + HOOKED.join(', '));
    log('');
    log('  ' + padR('类别', 22) + pad('平均', 14) + pad('峰值', 14) + pad('总计', 16));
    log('  ' + padR('ws2 收 · 完成(同步)', 22) +
        pad(rate(avg('recvDone', 1)), 14) + pad(rate(peak('recvDone')), 14) +
        pad(rate(total('recvDone')), 16));
    log('  ' + padR('ws2 收 · 请求', 22) +
        pad(rate(avg('recvReq', 1)), 14) + pad(rate(peak('recvReq')), 14) +
        pad(rate(total('recvReq')), 16));
    log('  ' + padR('ws2 发 · 完成(同步)', 22) +
        pad(rate(avg('sendDone', 1)), 14) + pad(rate(peak('sendDone')), 14) +
        pad(rate(total('sendDone')), 16));
    log('  ' + padR('ws2 发 · 请求', 22) +
        pad(rate(avg('sendReq', 1)), 14) + pad(rate(peak('sendReq')), 14) +
        pad(rate(total('sendReq')), 16));
    log('  ' + padR('overlapped 完成', 22) +
        pad(rate(avg('ovDone', 1)), 14) + pad(rate(peak('ovDone')), 14) +
        pad(rate(total('ovDone')), 16));
    log('  ' + padR('IOCP 完成 ← 最准', 22) +
        pad(rate(avg('iocpDone', 1)), 14) + pad(rate(peak('iocpDone')), 14) +
        pad(rate(total('iocpDone')), 16));
    log('  ' + padR('ReadFile 完成', 22) +
        pad(rate(avg('readDone', 1)), 14) + pad(rate(peak('readDone')), 14) +
        pad(rate(total('readDone')), 16));
    log('');
    log('  异步占比：收 ' + CUM.recvPending + ' 次 pending / 发 ' +
        CUM.sendPending + ' 次 pending；IOCP 调用 ' + CUM.iocpCalls + ' 次');
    if (CUM.setRate) {
        log('  kernel 对照：set_rate ' + CUM.setRate + ' 次，平均下发 ' +
            rate(CUM.rateSum / CUM.setRate) + '，最后一次 ' + CUM.lastRate);
        log('               consume ' + CUM.consume + ' 次');
    }

    // ── 结论 ──
    log('');
    log('---------- 结论 ----------');
    var iocpRate = avg('iocpDone', 1);
    var recvDoneRate = avg('recvDone', 1);
    var ovRate = avg('ovDone', 1);
    // "真实吞吐"取几者中最大的（不同程序走不同路径）
    var real = Math.max(iocpRate, recvDoneRate, ovRate, avg('readDone', 1));
    var cRate = CUM.setRate ? (CUM.rateSum / CUM.setRate) : 0;

    log('  实测"真实吞吐" ≈ ' + rate(real) +
        '（取 IOCP/WSARecv/Overlapped/ReadFile 的最大值）');

    if (real === 0) {
        log('  ⚠ 一个字节都没有。可能：');
        log('    ① 这次没在下载（或者已下完）');
        log('    ② 数据不走 ws2_32/IOCP 这条路（少见，但要确认）');
        log('    ③ 采样窗口太早，重新 start() 后等 20 秒');
    } else if (CUM.setRate && cRate > 0 && real > cRate * 0.85) {
        log('  ⚠ 真实吞吐已经贴近/超过平均下发速率（' + rate(cRate) + '）。');
        log('    → 令牌桶在这一刻确实在限制你。用 boost() 后应该能看到提升。');
    } else if (CUM.setRate && cRate > 0 && real < cRate * 0.5) {
        log('  ⚠ 真实吞吐只有下发速率的 ' + Math.round(real * 100 / cRate) + '%。');
        log('    → **桶给了配额，但数据没进来**。瓶颈不在 token bucket。');
        log('    下一步：看 timeline() 里"收(请求)"这一列。');
        log('      · 请求也很小 → 客户端根本没发够请求（并发/调度问题）');
        log('      · 请求很大但完成很小 → 服务端/CDN 不给数据（网络侧）');
    } else {
        log('  真实吞吐 ' + rate(real) + '。请把上面整段发我，我对照桶的配额判断。');
    }
    log('==========================================');
    log('');
}

function timeline(n) {
    n = n || 20;
    if (!WINDOWS.length) { log('  还没有数据'); return; }
    var start = Math.max(0, WINDOWS.length - n);
    log('');
    log('=== 每个窗口的明细（最近 ' + (WINDOWS.length - start) + ' 个）===');
    log('  ' + padR('t(s)', 8) + padR('收完成', 12) + padR('收请求', 12) +
        padR('IOCP', 12) + padR('发', 12) + padR('consume', 9));
    var acc = 0;
    for (var i = start; i < WINDOWS.length; i++) {
        var w = WINDOWS[i];
        acc += w.dt;
        log('  ' + padR(acc.toFixed(1), 8) +
            padR(rate(w.d.recvDone / w.dt), 12) +
            padR(rate(w.d.recvReq / w.dt), 12) +
            padR(rate(w.d.iocpDone / w.dt), 12) +
            padR(rate(w.d.sendDone / w.dt), 12) +
            padR(w.d.consume, 9));
    }
    log('');
}

// ── 启动 ────────────────────────────────────────────────────────────────
(function main() {
    log('');
    log('=== throughput.js：实测吞吐 vs 令牌配额 ===');
    hookRecv('WSARecv', false);
    hookRecv('WSARecvFrom', true);
    hookSend('WSASend');
    hookSend('WSASendTo');
    hookOverlappedResult();
    hookIocp();
    hookReadFile();
    hookKernel();
    log('');
    log('    已挂：' + HOOKED.join(', '));
    log('    现在点一个下载，等 20~40 秒，然后敲：report()');
    log('    实时看：live()    明细：timeline()    停止：stop()');
    log('');
    start();
})();
