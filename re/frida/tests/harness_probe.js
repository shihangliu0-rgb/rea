// 用假 Frida API 跑 probe.js，验证调用栈统计逻辑
// 用法： node harness_probe.js <probe.js> <size_hex>
const fs = require('fs');
const path = require('path');

const PROBE = process.argv[2];
const SIZE = parseInt(process.argv[3] || '0x2b25000', 16);
const src = fs.readFileSync(PROBE, 'utf8');

const MODBASE = 0x78100000;
// 另一块"非 kernel"区域，用来验证过滤
const OTHER_BASE = 0x75000000;
const OTHER_SIZE = 0x100000;

const logs = [];
const origLog = console.log;
console.log = (...a) => logs.push(a.join(' '));
global.send = () => {};
global.setTimeout = (fn) => { /* 不自动跑 */ return 0; };
global.setInterval = () => 0;
global.setImmediate = (fn) => { try { fn(); } catch (e) { } };
global.clearInterval = () => { };
global.hexdump = () => '';

function Ptr(v) {
  if (!(this instanceof Ptr)) return new Ptr(v);
  this.v = (v === undefined ? 0 : v) >>> 0;
}
Ptr.prototype.add = function (n) { return new Ptr((this.v + (n >>> 0)) >>> 0); };
Ptr.prototype.sub = function (n) { return new Ptr((this.v - (n >>> 0)) >>> 0); };
Ptr.prototype.toInt32 = function () { return this.v | 0; };
Ptr.prototype.toUInt32 = function () { return this.v >>> 0; };
Ptr.prototype.toString = function () { return '0x' + this.v.toString(16); };
Ptr.prototype.compare = function (o) { return this.v === o.v ? 0 : (this.v < o.v ? -1 : 1); };
Ptr.prototype.isNull = function () { return this.v === 0; };
Ptr.prototype.readPointer = function () { return new Ptr(0); };
Ptr.prototype.readU32 = function () { return 0; };
Ptr.prototype.readS32 = function () { return 0; };
Ptr.prototype.readU8 = function () { return 0; };
Ptr.prototype.writeU32 = function () { return this; };
// probe.js 里只有 bytesOk 会读字节：按 RVA 返回真实签名
const SIGBYTES = {
  0xdd320: '8b 44 24 04 85 c0',
  0xdd340: '53 57 56 89 ce',
  0xdb150: '8b 44 24 04 85 c0',
  0xdb170: '53 57 56 89 ce',
};
Ptr.prototype.readByteArray = function (len) {
  const want = (len === undefined) ? 8 : len;
  const hex = SIGBYTES[this.v - MODBASE];
  if (!hex) return new ArrayBuffer(want);
  const b = new Uint8Array(hex.split(' ').map(x => parseInt(x, 16))).buffer;
  return b.byteLength === want ? b : b.slice(0, want);
};

const mods = [
  { name: 'kernel.dll', path: 'C:\\p\\kernel.dll', base: new Ptr(MODBASE), size: SIZE },
  { name: 'netbase.dll', path: 'C:\\p\\netbase.dll', base: new Ptr(OTHER_BASE), size: OTHER_SIZE },
];

global.Process = {
  findModuleByName(n) {
    return mods.find(m => m.name.toLowerCase() === String(n).toLowerCase()) || null;
  },
  getModuleByName(n) {
    const m = this.findModuleByName(n);
    if (!m) throw new Error('not found');
    return m;
  },
  findModuleByAddress(a) {
    const v = (a && a.v !== undefined) ? a.v : a;
    for (const m of mods) {
      if (v >= m.base.v && v < m.base.v + m.size) return m;
    }
    return null;
  },
  enumerateModules() { return mods; },
  getCurrentThreadId() { return 1; },
  arch: 'ia32', pointerSize: 4, id: 28704,
};

global.Module = {
  getGlobalExportByName() { throw new Error('no'); },
  findGlobalExportByName() { return null; },
};
global.Memory = { alloc: () => new Ptr(0x1000), protect: () => true, scanSync: () => [] };

// 让测试能控制"下一次 backtrace 返回什么"
let NEXT_STACK = [];
global.Backtracer = { ACCURATE: 'accurate', FUZZY: 'fuzzy' };
global.Thread = {
  sleep() { },
  backtrace(ctx, which) {
    const s = NEXT_STACK.length ? NEXT_STACK : [];
    return s.map(v => new Ptr(v));
  },
};

const attached = [];
global.Interceptor = {
  attach(addr, cb) {
    attached.push({ addr: addr.sub(mods[0].base).toInt32(), cb });
    return { detach() { } };
  },
};

global.ptr = function (x) { return (typeof x === 'object' && x) ? x : new Ptr(x); };

// 执行
let err = null;
try { eval(src); } catch (e) { err = e; }
console.log = origLog;

let fail = 0;
function check(cond, msg) {
  if (cond) origLog('   OK  ' + msg);
  else { origLog('   FAIL ' + msg); fail++; }
}

if (err) { origLog('   FAIL eval 抛异常: ' + err.message); fail++; }
origLog('   挂上的 hook: ' + attached.map(a => '0x' + a.addr.toString(16)).join(', '));
check(attached.length === 2, '挂了 set_rate + consume 两个点');

const rateHook = attached.find(a => a.addr === (SIZE === 0x2b25000 ? 0xdd320 : 0xdb150));
const consumeHook = attached.find(a => a.addr === (SIZE === 0x2b25000 ? 0xdd340 : 0xdb170));
check(!!rateHook, 'set_rate hook 地址正确');
check(!!consumeHook, 'consume hook 地址正确');

// 模拟：set_rate(16384) 被 0x2e82bc 调用 3 次，被 0xdd1e0 调用 1 次
// 栈里第一个 kernel frame 是 caller，后面跟 netbase（应被过滤）
const ctx = { context: { esp: new Ptr(0x1234) } };
function fireSetRate(rate, callerRva, n) {
  for (let i = 0; i < n; i++) {
    NEXT_STACK = [
      MODBASE + callerRva,        // caller（kernel.dll 内）
      OTHER_BASE + 0x1234,        // 非 kernel → 应被跳过
      MODBASE + 0x100000,         // 更深一层
    ];
    rateHook.cb.onEnter.call(ctx, [new Ptr(rate)]);
  }
}

if (rateHook) {
  fireSetRate(16384, 0x2e82bc, 3);
  fireSetRate(16384, 0xdd1e0, 1);
  fireSetRate(1006860, 0x2e82bc, 2);
  // 大量值（>16MiB/s）不应计入明细，只记总数
  fireSetRate(0x1F400000, 0x2e82bc, 4);
}

// consume 10 次
NEXT_STACK = [MODBASE + 0x2e82bc];
if (consumeHook) {
  for (let i = 0; i < 10; i++) consumeHook.cb.onEnter.call(ctx, []);
}

// 调 report()
origLog('\n--- report() 输出 ---');
logs.length = 0;
console.log = (...a) => logs.push(a.join(' '));      // ← 必须重新接管
try { report(); } catch (e) { origLog('   FAIL report() 抛异常: ' + e.message); fail++; }
console.log = origLog;                                // ← 再切回
const out = logs.join('\n');
origLog(out.replace(/^/gm, '   | '));

// 断言
check(/set_rate 共 10 次/.test(out), 'set_rate 总数 = 10（3+1+2+4）');
check(/0x2e82bc\s+×9/.test(out), '0x2e82bc 被统计 9 次（3+2+4）');
check(/0xdd1e0\s+×1/.test(out), '0xdd1e0 被统计 1 次');
check(/consume 共 10 次/.test(out), 'consume 总数 = 10（无重复计数）');
check(/16384/.test(out), '速率分布里出现 16384');
check(/1006860/.test(out), '速率分布里出现 1006860');

// chains()
logs.length = 0;
console.log = (...a) => logs.push(a.join(' '));
try { chains(5); } catch (e) { origLog('   FAIL chains() 抛异常: ' + e.message); fail++; }
console.log = origLog;
const ch = logs.join('\n');
check(/调用链样本/.test(ch), 'chains() 可调用');
check(!/netbase/.test(ch), '调用链里过滤掉了非 kernel.dll 的 frame');

// reset()
logs.length = 0;
console.log = (...a) => logs.push(a.join(' '));
try { reset(); report(); } catch (e) { origLog('   FAIL reset 后 report 抛异常: ' + e.message); fail++; }
console.log = origLog;
const rl = logs.join('\n');
check(/还没有任何命中/.test(rl), 'reset() 之后统计清零');

// 地址格式：不能出现 0x0x
check(!/0x0x/.test(out + ch), '地址格式正确（没有 0x0x）');

origLog('');
origLog(fail === 0 ? 'HARNESS PASS' : 'HARNESS FAIL x' + fail);
process.exit(fail === 0 ? 0 : 1);
