/*
 * re/frida/hooks.js —— 百度网盘下载内核限速链路的动态验证点
 *
 * 用法（Windows，需 root/管理员）:
 *   frida -f "C:\Program Files\Baidu\BaiduNetdisk\BaiduNetdisk.exe" -l hooks.js --runtime=v8
 *   # 或附加:
 *   frida -n BaiduNetdisk.exe -l hooks.js
 *
 * 注意:
 * 1) kernel.dll 有 TLS 回调和 IsDebuggerPresent 检查，建议用 frida 的 -f（spawn）方式，
 *    本脚本会自动 patch IsDebuggerPresent / CheckRemoteDebuggerPresent 返回 0。
 * 2) 全部地址都是 **RVA**，脚本里用 "模块基址 + RVA" 计算。
 * 3) 只挂"读参数 / 读返回值"的点，不改行为；要验证"是不是这个点在限速"，
 *    把 PATCH_CONSUME 改成 true 即可（会把令牌桶永远填满）。
 */

const KERNEL = 'kernel.dll';
const PATCH_CONSUME = false;   // true = 实验性解限（仅用于验证机制，不要用于日常使用）

// ---------- 基础设施 ----------
function base(name) {
    const m = Process.findModuleByName(name);
    if (!m) { console.log('[!] 模块未加载: ' + name); return null; }
    return m.base;
}

function hexr(p, len) {
    try { return hexdump(p, { length: len, ansi: false }); } catch (e) { return '<unreadable>'; }
}

function u32(p) { return p.readU32(); }
function u64(p) {
    const lo = p.readU32();
    const hi = p.add(4).readU32();
    return hi * 4294967296 + lo;
}
function cstr(p) {
    try {
        if (p.isNull()) return null;
        const s = p.readUtf8String(200);
        return s;
    } catch (e) { return null; }
}

// 反调试：把常见检测点打成恒假
function neuterAntiDebug() {
    ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'].forEach(fn => {
        const a = Module.findExportByName('kernel32.dll', fn);
        if (a) {
            Interceptor.replace(a, new NativeCallback(function () { return 0; }, 'int', ['pointer', 'pointer']));
            console.log('[+] 已屏蔽 ' + fn);
        }
    });
}

// ---------- 通用: 打日志 ----------
function hook(rva, label, onEnter, onLeave) {
    const b = base(KERNEL);
    if (!b) return;
    const addr = b.add(rva);
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.ecx = this.context.ecx;                 // 保存 __thiscall 的 this
                if (onEnter) onEnter.call(this, args);
            },
            onLeave: function (ret) {
                if (onLeave) onLeave.call(this, ret);
            }
        });
        console.log('[+] hook ' + label + ' @ ' + addr + ' (RVA 0x' + rva.toString(16) + ')');
    } catch (e) {
        console.log('[!] hook 失败 ' + label + ': ' + e);
    }
}

// ---------- 业务 hook ----------
function install() {
    neuterAntiDebug();

    // 1) set_param(type, value) —— 服务端下发的一切参数（147 类）
    //    __stdcall set_param(int type, const char* value)
    hook(0x1225f0, 'set_param', (args) => {
        const type = args[0].toInt32();
        const val = cstr(args[1]);
        const show = (val && val.length > 160) ? val.substring(0, 160) + '…' : val;
        console.log(`[set_param] type=${type} value=${JSON.stringify(show)}`);
        return null;
    });

    // 2) SpeedControl::update_max_speed(uint64)  this = ecx
    hook(0x2dd200, 'update_max_speed', function (args) {
        const th = this.context.ecx;
        const old = u64(th.add(0x40));
        const neu = args[0].toUInt32() + args[1].toUInt32() * 4294967296;
        console.log(`[max_speed] ${old} -> ${neu} B/s`);
        return null;
    });

    // 3) SpeedControl::set_restrict_ratio(int)  this = ecx
    hook(0x2dcde0, 'set_restrict_ratio', function (args) {
        const th = this.context.ecx;
        console.log(`[ratio] old=${th.add(0x38).readS32()}% new=${args[0].toInt32()}%`);
        return null;
    });

    // 4) SpeedControl::calculate_target_speed() —— 返回值就是本 tick 的目标速率
    //    该函数体在 0x2ddb90，尾块在 0x2de43e
    // 注意: 该函数用 and esp,0xfffffff8 对齐栈, 不能用 this.context.ecx 取 this
    hook(0x2ddb90, 'calculate_target_speed', null, function (ret) {
        const v = ret.toUInt32();
        if (v !== 0x1F400000) console.log(`[target] ${v} B/s (${(v / 1024).toFixed(1)} KiB/s)`);
        else console.log('[target] 不限 (哨兵 0x1F400000)');
    });

    // 5) TokenBucket::set_rate(uint32) —— 每个 peer 的实际配额
    //    __thiscall: ecx = this, 参数入栈
    hook(0x2db150, 'bucket.set_rate', function (args) {
        const th = this.context.ecx;
        console.log(`[bucket] rate=${args[0].toUInt32()} B/s cap=${th.add(8).readU32()}`);
        return null;
    });

    // 6) TokenBucket::consume() —— 真正扣令牌；返回 0 表示"这个 tick 不许发请求"
    hook(0x2db170, 'bucket.consume', null, function (ret) {
        if (ret.toUInt32() === 0) console.log('[bucket] 无令牌 -> 本 tick 抑制请求');
    });

    // 7) cdn_speed_limit_dispatch —— 每任务 CDN 配额
    hook(0x2ed84e, 'cdn_speed_limit_dispatch', () => { console.log('[cdn] dispatch 进入'); return null; });

    // 8) close cdn 决策入口（RVA 0x1aea38，核心块 0x1aeadc）
    hook(0x1aea38, 'close_cdn_strategy', function (args) {
        const th = this.context.ecx;
        console.log(`[close-cdn] level=${th.readS32()} speed[edi+0x20]=${th.add(0x20).readS32()}`);
        return null;
    });

    // 可选: 实验性解限（把 rate 无限放大）—— 仅用于验证"这个桶就是限速点"
    if (PATCH_CONSUME) {
        hook(0x2db170, 'bucket.consume(PATCH)', function (args) {
            const th = this.context.ecx;
            th.add(0x20).writeU32(0x1F400000);   // rate = 524288000 B/s
            th.add(8).writeU32(0x1F400000);      // cap
        });
    }
}

// kernel.dll 可能延迟加载
function waitKernel(cb, tries) {
    tries = tries || 0;
    if (Process.findModuleByName(KERNEL)) { cb(); return; }
    if (tries > 300) { console.log('[!] 等不到 ' + KERNEL); return; }
    setTimeout(() => waitKernel(cb, tries + 1), 200);
}

setImmediate(() => waitKernel(install));
