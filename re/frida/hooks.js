/*
 * re/frida/hooks.js —— 百度网盘下载内核限速链路的动态验证点
 * 目标：Frida 16.x / 17.x 通吃（17 删掉了 Module.findExportByName 等静态 API）
 *
 * 用法（Windows，管理员）:
 *   frida -f "D:\Wang_Pan\BaiduNetdisk\BaiduNetdisk.exe" -l hooks.js
 *   frida -n BaiduNetdisk.exe -l hooks.js
 *   # 本仓库自带的启动器（不需要 frida 命令）:
 *   python re/frida/run.py spawn --exe "D:\...\BaiduNetdisk.exe"
 *
 * 针对你遇到的 TypeError，三个关键改动:
 *   1) Module.findExportByName / getExportByName / findBaseAddress 在 Frida 17 已被删除，
 *      改用 Process.getModuleByName(name).getExportByName(sym)，全局查找用 Module.getGlobalExportByName。
 *      本脚本所有符号查找都走下面的 findExport() 兼容函数。
 *   2) 全脚本不用箭头函数（避免某些运行时的 `unexpected token '=>'`），统一 function + var。
 *   3) 每个 hook 在 attach 前先做字节签名校验，版本对不上就跳过并说明原因，
 *      而不是插到错地址把客户端搞崩。
 *
 * 全部地址都是 kernel.dll 的 RVA（基址 0x10000000），运行时用 模块基址+RVA 计算。
 * 默认只读不改；PATCH_RATE=true 才会写内存（仅用于验证"令牌桶就是限速点"）。
 */

var KERNEL = 'kernel.dll';
var KERNEL32 = 'kernel32.dll';

// 危险开关：默认 false。true 时把令牌桶 rate 写成 500MB/s（等于解除限速）。
var PATCH_RATE = false;

// 安静模式：true 时少打一些重复行
var QUIET = false;

// ---------------------------------------------------------------------------
// 0. 兼容层（Frida 17 的关键）
// ---------------------------------------------------------------------------

/** 按模块名取 Module 对象（17 里 Process.getModuleByName 找不到会抛异常，统一成返回 null） */
function getModule(name) {
    try {
        if (Process.findModuleByName) return Process.findModuleByName(name);
        return Process.getModuleByName(name);
    } catch (e) {
        return null;
    }
}

/** 兼容取导出符号地址：返回 NativePointer 或 null
 *  17+ : Process.getModuleByName(mod).findExportByName(sym) / Module.findGlobalExportByName(sym)
 *  16- : Module.findExportByName(mod, sym)
 */
function findExport(modName, symName) {
    // 1) 模块对象上的实例方法（17 推荐写法，16 也支持）
    var m = getModule(modName);
    if (m && m.findExportByName) {
        try {
            var p = m.findExportByName(symName);
            if (p) return p;
        } catch (e) { /* 继续尝试旧写法 */ }
    }
    // 2) 旧静态 API（16 及更早）
    if (Module.findExportByName) {
        try {
            var q = Module.findExportByName(modName, symName);
            if (q) return q;
        } catch (e) { }
    }
    // 3) 17+ 全局查找（不带模块名）
    var globalFn = Module.findGlobalExportByName || Module.getGlobalExportByName;
    if (globalFn) {
        try {
            var r = globalFn(symName);
            if (r) return r;
        } catch (e) { }
    }
    return null;
}

/** 读一段字节做签名校验 */
function bytesAt(addr, hexstr) {
    var want = hexstr.split(' ').join('').toLowerCase();
    var got;
    try {
        got = addr.readByteArray(want.length / 2);
    } catch (e) {
        return false;
    }
    var u8 = new Uint8Array(got);
    for (var i = 0; i < u8.length; i++) {
        var h = u8[i].toString(16);
        if (h.length < 2) h = '0' + h;
        if (h !== want.substr(i * 2, 2)) return false;
    }
    return true;
}

function readHexAt(addr, nbytes) {
    try {
        var arr = new Uint8Array(addr.readByteArray(nbytes));
        var s = '';
        for (var i = 0; i < arr.length; i++) {
            s += (arr[i] < 16 ? '0' : '') + arr[i].toString(16) + ' ';
        }
        return s.trim();
    } catch (e) {
        return '?';
    }
}

// ---------------------------------------------------------------------------
// 1. 通用工具
// ---------------------------------------------------------------------------

// SEND_DUP=true 时额外走 send 通道（run.py 用得到；frida CLI 会因此多打印一行 message: {...}）
var SEND_DUP = false;

function log(msg) {
    console.log(msg);
    if (SEND_DUP) {
        try { send({ tag: 'log', text: msg }); } catch (e) { }
    }
}

function base(name) {
    var m = getModule(name);
    if (!m) return null;
    return m.base;
}

function u64(p) {
    var lo = p.readU32();
    var hi = p.add(4).readU32();
    return hi * 4294967296 + lo;
}

function cstr(p) {
    try {
        if (p.isNull()) return null;
        return p.readUtf8String(200);
    } catch (e) { return null; }
}

/** 读 vtable 的第 n 个槽（用来确认 this 真的是 TokenBucket） */
function vtableSlot(obj, n) {
    try {
        var v = obj.readPointer();
        if (v.isNull()) return null;
        return v.add(n * Process.pointerSize).readPointer();
    } catch (e) {
        return null;
    }
}

/** 确认 obj 是不是 AccumulateTokenBucket：vtable+4 必须指向 0xdb150 */
function isTokenBucket(obj, kernelBase) {
    if (!obj) return false;
    var g = vtableSlot(obj, 1);
    if (!g) return false;
    return g.equals(kernelBase.add(0xdb150));
}

// ---------------------------------------------------------------------------
// 2. 反调试：只改返回值，不动函数体
//    IsDebuggerPresent() -> 0
//    CheckRemoteDebuggerPresent(hProcess, &b) -> 0 且 *b = 0
// ---------------------------------------------------------------------------

function neuterAntiDebug() {
    var done = neuterAntiDebug.done || (neuterAntiDebug.done = {});

    if (!done.isdbg) {
        var a = findExport(KERNEL32, 'IsDebuggerPresent');
        if (a) {
            try {
                Interceptor.attach(a, {
                    onLeave: function (retval) { retval.replace(0); }
                });
                done.isdbg = true;
                log('[+] 已屏蔽 IsDebuggerPresent @ ' + a);
            } catch (e) {
                log('[!] 屏蔽 IsDebuggerPresent 失败: ' + e);
            }
        } else {
            log('[!] 找不到 IsDebuggerPresent（跳过，不影响其它 hook）');
        }
    }

    if (!done.remotedbg) {
        var b = findExport(KERNEL32, 'CheckRemoteDebuggerPresent');
        if (b) {
            try {
                Interceptor.attach(b, {
                    onEnter: function (args) {
                        // args[1] = PBOOL，先清零，再让原函数去写
                        try { args[1].writeU32(0); } catch (e) { }
                        this.pOut = args[1];
                    },
                    onLeave: function (retval) {
                        retval.replace(0);
                        try { this.pOut.writeU32(0); } catch (e) { }
                    }
                });
                done.remotedbg = true;
                log('[+] 已屏蔽 CheckRemoteDebuggerPresent @ ' + b);
            } catch (e) {
                log('[!] 屏蔽 CheckRemoteDebuggerPresent 失败: ' + e);
            }
        } else {
            log('[!] 找不到 CheckRemoteDebuggerPresent（跳过）');
        }
    }
}

// ---------------------------------------------------------------------------
// 3. hook 封装：attach 前做签名校验
// ---------------------------------------------------------------------------

/**
 * @param rva     kernel.dll 里的 RVA
 * @param label   显示名
 * @param sig     期望的起始字节（空格分隔 hex），null 表示不校验
 * @param onEnter function(args)，this.thisPtr 是 ecx
 * @param onLeave function(retval)
 */
function hook(rva, label, sig, onEnter, onLeave) {
    var b = base(KERNEL);
    if (!b) return false;
    var addr = b.add(rva);

    if (sig && !bytesAt(addr, sig)) {
        log('[!] 跳过 ' + label + '：RVA 0x' + rva.toString(16) +
            ' 处字节不匹配（客户端版本不同？）期望=' + sig +
            ' 实际=' + readHexAt(addr, sig.split(' ').length));
        return false;
    }

    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try { this.thisPtr = this.context.ecx; } catch (e) { this.thisPtr = null; }
                if (onEnter) onEnter.call(this, args);
            },
            onLeave: function (retval) {
                if (onLeave) onLeave.call(this, retval);
            }
        });
        log('[+] hook ' + label + ' @ ' + addr + ' (RVA 0x' + rva.toString(16) + ')');
        return true;
    } catch (e) {
        log('[!] hook 失败 ' + label + ': ' + e);
        return false;
    }
}

// ---------------------------------------------------------------------------
// 4. 业务 hook
// ---------------------------------------------------------------------------

var INSTALLED = false;

function install() {
    if (INSTALLED) return;
    INSTALLED = true;
    neuterAntiDebug();

    var kb = base(KERNEL);
    var ok = 0, bad = 0;
    function mark(r) { if (r) ok++; else bad++; }

    // 1) set_param(type, value)  __stdcall，服务端下发的一切参数（147 类）
    mark(hook(0x1225f0, 'set_param', '55 89 e5 53 57 56 83 ec 2c',
        function (args) {
            var type = args[0].toInt32();
            var val = cstr(args[1]);
            var show = (val && val.length > 160) ? val.substring(0, 160) + '…' : val;
            log('[set_param] type=' + type + ' value=' + JSON.stringify(show));
        }, null));

    // 2) SpeedLimitor::update_max_speed(uint64)   this = ecx
    mark(hook(0x2dd200, 'update_max_speed', '55 89 e5 53 57 56 83 e4 f8',
        function (args) {
            var th = this.thisPtr;
            if (!th) return;
            var old = u64(th.add(0x40));
            var neu = args[0].toUInt32() + args[1].toUInt32() * 4294967296;
            log('[max_speed] ' + old + ' -> ' + neu + ' B/s');
        }, null));

    // 3) SpeedLimitor::set_restrict_ratio(int)   this = ecx
    mark(hook(0x2dcde0, 'set_restrict_ratio', '55 89 e5 53 57 56 81 ec',
        function (args) {
            var th = this.thisPtr;
            if (!th) return;
            log('[ratio] old=' + th.add(0x38).readS32() + '% new=' + args[0].toInt32() + '%');
        }, null));

    // 4) calculate_target_speed() —— 返回值就是本 tick 的目标速率
    //    该函数有 `and esp,0xfffffff8`，栈被重对齐，不能用 ecx 取 this
    mark(hook(0x2ddb90, 'calculate_target_speed', '55 89 e5 53 57 56 83 e4 f8',
        null, function (retval) {
            var v = retval.toUInt32();
            if (v === 0x1F400000) {
                if (!QUIET) log('[target] 不限 (哨兵 0x1F400000)');
            } else {
                log('[target] ' + v + ' B/s (' + (v / 1024).toFixed(1) + ' KiB/s)');
            }
        }));

    // 5) TokenBucket::set_rate(uint32) —— 每个通道的实际配额
    //    ⚠️ 正确 RVA 是 0xdb150（0x118cb44 vtable: [set_rate, dtor, consume]）
    mark(hook(0xdb150, 'bucket.set_rate', '8b 44 24 04 85 c0',
        function (args) {
            var th = this.thisPtr;
            if (!th) return;
            if (!isTokenBucket(th, kb)) return;      // 只认真桶，过滤误中
            log('[bucket] rate=' + args[0].toUInt32() + ' B/s cap=' + th.add(8).readU32());
        }, null));

    // 6) TokenBucket::consume() —— 真正扣令牌，返回 0 表示本 tick 不发请求
    //    ⚠️ 正确 RVA 是 0xdb170
    mark(hook(0xdb170, 'bucket.consume', '53 57 56 89 ce',
        function () {
            // 记录 this，onLeave 时用来判断是不是真桶
            this.maybeBucket = this.thisPtr;
        },
        function (retval) {
            if (!isTokenBucket(this.maybeBucket, kb)) return;
            if (retval.toUInt32() === 0) log('[bucket] 无令牌 -> 本 tick 抑制请求');
        }));

    // 7) cdn_speed_limit_dispatch —— 每任务 CDN 配额
    mark(hook(0x2ed84e, 'cdn_speed_limit_dispatch', '8b 0b e8',
        function () { if (!QUIET) log('[cdn] dispatch 进入'); }, null));

    // 8) close cdn 决策块内部（0x1aea38 体内 0x1aeb6d，此时 base/cdn_speed 已算好）
    //    注意这里 ecx 是 level 而不是 this，对象在 [ebp-0x30]
    mark(hook(0x1aeb6d, 'close_cdn(decided)', '8b 7d d0 0f af ce',
        function () {
            var ebp = this.context.ebp;
            var level = ebp.add(-0xec).readS32();
            var basev = ebp.add(-0xd8).readS32();
            var cdnSpeed = ebp.add(-0xd4).readS32();
            var measured = ebp.add(-0x30).readPointer().add(0x20).readS32();
            log('[close-cdn] level=' + level + ' base=' + basev +
                ' cdn_speed=' + cdnSpeed + ' (' + (cdnSpeed / 1048576).toFixed(2) + ' MiB/s)' +
                ' gate=' + (level * basev) + ' measured=' + measured);
        }, null));

    // ===== 9) 试用提速（SVIP trial）=====
    //  on=true  → 4 个令牌桶全部 set_rate(0x1F400000)   ← 这就是"提速"
    //  on=false → 从快照整块还原                        ← 这就是"台阶式掉回去"
    var trialStart = null;
    mark(hook(0xe2fb0, 'set_try_speedup_flag', '55 89 e5 53 57 56 81 ec',
        function (args) {
            var on = args[0].toInt32() & 0xff;
            var th = this.thisPtr;
            var state = th ? th.add(0x1c0).readU8() : -1;
            log('[trial] on=' + on + ' state_before=' + state);

            if (on && trialStart === null) {
                trialStart = Date.now();
                if (th) {
                    var offs = [0x00, 0x38, 0xe0, 0x150];
                    for (var i = 0; i < offs.length; i++) {
                        var bk = th.add(offs[i]);
                        log('          bucket+0x' + offs[i].toString(16) +
                            ': rate=' + bk.add(0x20).readU32() +
                            ' cap=' + bk.add(8).readU32());
                    }
                }
            } else if (!on && trialStart !== null) {
                log('[trial] 持续时间 ≈ ' + ((Date.now() - trialStart) / 1000).toFixed(1) + ' s');
                trialStart = null;
            }
        }, null));

    // ===== 10) 收尾门控：门限 ∝ rate（06 篇的核心证据）=====
    mark(hook(0x1afd38, 'block_gate(pre)', '29 d8 89 86 f0 00 00 00',
        function () {
            var esi = this.context.esi;
            log('[gate] left_block=' + esi.add(0xf0).readS32() +
                ' rate=' + esi.add(0xe4).readS32() +
                ' ratio=' + esi.add(0xe0).readS32());
        }, null));

    mark(hook(0x1affb3, 'download_threshold', 'f2 0f 59 0d',
        function () {
            var esi = this.context.esi;
            log('[threshold] download_threshold_speed=' + esi.add(0xbc).readS32() +
                ' B/s (= 桶容量 = rate，rate 越大门槛越高)');
        }, null));

    // ===== 11) restrict_ratio 的唯一外部写入口（vtable 槽 0x119c8d0）=====
    mark(hook(0x27fee0, 'set_download_restrict_ratio', '55 89 e5 53 57 56 81 ec',
        function (args) {
            log('[ratio] new=' + args[0].toInt32() + '%');
        }, null));

    // 可选：实验性解限（把 rate 顶到 500MB/s）
    if (PATCH_RATE) {
        log('[!] PATCH_RATE=true —— 正在修改令牌桶速率（仅用于验证机制）');
        mark(hook(0xdb170, 'bucket.consume(PATCH)', '53 57 56 89 ce',
            function () {
                var th = this.thisPtr;
                if (!isTokenBucket(th, kb)) return;
                th.add(0x20).writeU32(0x1F400000);
                th.add(8).writeU32(0x1F400000);
            }, null));
    }

    log('========== 安装完成：成功 ' + ok + ' 个，跳过 ' + bad + ' 个 ==========');
    if (ok === 0) {
        log('[!] 一个都没挂上。检查：1) kernel.dll 是否已加载（先开始一个下载）');
        log('                      2) 客户端版本是否 8.1.6.101');
    }
}

// ---------------------------------------------------------------------------
// 5. 等 kernel.dll 加载
// ---------------------------------------------------------------------------

function waitKernel(cb, tries) {
    tries = tries || 0;
    if (getModule(KERNEL)) { cb(); return; }
    if (tries > 900) {
        log('[!] 等了 3 分钟还是没看到 kernel.dll —— 跑 diagnose() 看原因');
        diagnose();
        return;
    }
    if (tries > 0 && tries % 50 === 0) {
        var secs = (tries / 5).toFixed(0);
        log('[*] 仍在等 kernel.dll…（约 ' + secs + ' 秒）');
        if (tries % 150 === 0) diagnose();   // 每 30 秒自动体检一次
    }
    setTimeout(function () { waitKernel(cb, tries + 1); }, 200);
}

// ---------------------------------------------------------------------------
// 5.5 诊断：为什么 kernel.dll 没加载
// ---------------------------------------------------------------------------

function listModules() {
    var out = [];
    try {
        // 只列 .dll/.exe，别把几百个堆块也打出来
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            var nm = mods[i].name || '';
            if (/\.(dll|exe)$/i.test(nm)) out.push(nm);
        }
    } catch (e) {
        // 17 之后 enumerateModules 仍在，但保险起见退回逐个探测
        var names = ['BaiduNetdisk.exe', 'YunLogic.dll', 'Bull140U.dll', 'YunDls.dll',
                     'KernelCom.dll', 'channelpcsdk.dll', 'netbase.dll', 'kernel.dll',
                     'kernel_btsdk.dll', 'speedtest.dll'];
        for (var j = 0; j < names.length; j++) {
            if (getModule(names[j])) out.push(names[j]);
        }
    }
    return out;
}

function diagnose() {
    log('---------- 诊断 ----------');
    var mods = listModules();
    log('已加载模块数：' + mods.length);

    var watch = ['BaiduNetdisk.exe', 'YunLogic.dll', 'Bull140U.dll', 'YunDls.dll',
                 'KernelCom.dll', 'channelpcsdk.dll', 'netbase.dll', 'kernel.dll',
                 'kernel_btsdk.dll', 'speedtest.dll'];
    for (var i = 0; i < watch.length; i++) {
        var m = getModule(watch[i]);
        log('  ' + (m ? '[已加载] ' : '[  --  ] ') + watch[i] +
            (m ? ('  base=' + m.base + ' size=' + (m.size / 1048576).toFixed(1) + 'MB') : ''));
    }

    var hasLoader = !!getModule('YunDls.dll');
    if (!hasLoader) {
        log('[!] 连 YunDls.dll 都没加载 → 说明"下载内核"这块业务还没被初始化。');
        log('    最可能的原因：客户端停在了登录/首屏，或者调用方不是被 Frida spawn 的这个进程。');
    } else {
        log('[i] YunDls.dll 已在 → 下载内核随时可能按需 LoadLibrary("kernel.dll")。');
        log('    现在去客户端里点一个下载（任意文件），kernel.dll 会立刻加载。');
    }

    // 进程命令行（确认是不是同一个 exe）
    try {
        if (Process.commandLine) log('命令行：' + Process.commandLine);
    } catch (e) { }

    log('[i] 如果客户端是多进程结构，下载可能在另一个 pid 里：');
    log('    frida-ps | findstr /i baidu     （或 python re/frida/dump_ps.py baidu）');

    // 打印"最近加载的 15 个模块"——用来看初始化走到哪一步了
    try {
        var mods2 = Process.enumerateModules();
        var tail = [];
        for (var k = Math.max(0, mods2.length - 15); k < mods2.length; k++) {
            tail.push(mods2[k].name);
        }
        log('最近加载的模块：' + tail.join(', '));
    } catch (e) { }

    log('[i] 提示：kernel.dll 是"用到才加载"的（客户端按需 LoadLibrary）。');
    log('    - 如果连 YunDls.dll 都没有 → 客户端还没进到能下载的状态（登录/首屏）');
    log('    - 如果 YunDls.dll 有、kernel.dll 没有 → 点一个下载就会加载');
    log('    - 如果是 spawn 起的进程，VMProtect 可能干扰初始化 → 改用 attach');
    log('--------------------------');
}

// ---------------------------------------------------------------------------
// 6. 启动
// ---------------------------------------------------------------------------

log('[i] 脚本开始运行，pid=' + Process.id + '，指针宽度=' + Process.pointerSize * 8 + ' 位');

// 反调试检查在启动瞬间就跑了，先立刻打一次（spawn 模式下 kernel.dll 还没出现）
neuterAntiDebug();

// 首次诊断：3 秒后告诉用户当前加载了什么
setTimeout(function () {
    if (getModule(KERNEL)) return;
    log('[*] 3 秒了，kernel.dll 还没出现。先看一眼当前状态：');
    diagnose();
}, 3000);

// 优先用模块观察者（事件驱动，kernel.dll 一加载立刻挂）—— Frida 17 有，16 可能没有
var watched = false;
try {
    if (Process.attachModuleObserver) {
        Process.attachModuleObserver({
            onAdded: function (m) {
                var n = (m.name || '').toLowerCase();
                if (n === KERNEL.toLowerCase()) {
                    log('[+] kernel.dll 加载了 @ ' + m.base + '（模块观察者触发）');
                    install();
                } else if (n === 'yundls.dll') {
                    log('[i] YunDls.dll 已加载 → 下载内核快要初始化了');
                }
            }
        });
        watched = true;
        log('[i] 已注册模块观察者，等 kernel.dll 加载');
    }
} catch (e) {
    log('[i] 模块观察者不可用（' + e + '），改用轮询');
}

if (!watched) {
    setImmediate(function () {
        waitKernel(install);
    });
}

// 兜底：观察者模式下也定期查一次，防止漏事件（install 幂等，重复触发无副作用）
if (watched) {
    var iv = setInterval(function () {
        if (INSTALLED) { clearInterval(iv); return; }
        if (getModule(KERNEL)) {
            log('[+] kernel.dll 已加载（轮询兜底发现）');
            clearInterval(iv);
            install();
        }
    }, 2000);
}
