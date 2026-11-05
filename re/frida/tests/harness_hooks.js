// 用假 Frida API 执行真实的 hooks.js，验证 242 的自动选表 + RVA 解析
const fs = require('fs');
const path = require('path');

const REALMAP = JSON.parse(require('fs').readFileSync(process.env.REAL_BYTES || require('path').join(__dirname, 'data', 'real242.json'), 'utf8'));

const HOOKS = process.argv[2];
const SIZE = parseInt(process.argv[3], 16);   // 0x2b25000
const src = fs.readFileSync(HOOKS, 'utf8');

const MODBASE = 0x78100000;
const sends = [];
const logs = [];

global.send = (o, d) => sends.push(o);
global.hexdump = () => '78100000  00 00 00 00';
global.setTimeout = () => 0;
global.setInterval = () => 0;
global.clearInterval = () => {};
global.clearTimeout = () => {};

function Ptr(v) {
  if (!(this instanceof Ptr)) return new Ptr(v);
  this.v = v >>> 0;
}
Ptr.prototype.add = function (n) { return new Ptr((this.v + (n >>> 0)) >>> 0); };
Ptr.prototype.sub = function (n) { return new Ptr((this.v - (n >>> 0)) >>> 0); };
Ptr.prototype.toInt32 = function () { return this.v | 0; };
Ptr.prototype.toString = function () { return '0x' + this.v.toString(16); };
Ptr.prototype.compare = function (o) { return this.v === o.v ? 0 : (this.v < o.v ? -1 : 1); };
Ptr.prototype.readU32 = function () { return 0; };
Ptr.prototype.readS32 = function () { return 0; };
Ptr.prototype.writeU32 = function () { return this; };
Ptr.prototype.readByteArray = function (len) {
  const want = (len === undefined || len === null) ? 8 : len;
  const rva = this.v - MODBASE;
  const buf = bytesForRva(rva);
  if (buf) {
    // 真实 Frida 严格按 len 返回，桩也必须一致
    return buf.byteLength === want ? buf : buf.slice(0, want);
  }
  return new ArrayBuffer(want);
};
Ptr.prototype.isNull = function () { return this.v === 0; };

const mod = {
  name: 'kernel.dll',
  path: 'D:\\Wang_Pan\\BaiduNetdisk\\kernel.dll',
  base: new Ptr(MODBASE),
  size: SIZE,
};

// 每个 RVA 处放"正确签名"，用于让 hook() 的字节校验通过
const SIGS = {
  0x125f20: '55 89 e5 53 57 56 83 ec',
  0x2e7e70: '55 89 e5 53 57 56 83 e4',
  0x2e7a50: '55 89 e5 53 57 56 81 ec',
  0x2e8800: '55 89 e5 53 57 56 83 e4',
  0xdd320: '8b 44 24 04 85 c0',
  0xdd340: '53 57 56 89 ce',
  0x2f83ae: '8b 0b e8',
  0x1b25bd: '8b 7d d0 0f af ce',
  0xe52c0: '55 89 e5 53 57 56 81 ec',
  0x1b3788: '29 d8 89 86 f0 00 00 00',
  0x1b3a03: 'f2 0f 59 0d',
  0x28a0f0: '55 89 e5 53 57 56 81 ec',
};
function bytesForRva(rva) {
  const hex = REALMAP['0x' + rva.toString(16)];
  if (!hex) return null;
  const arr = hex.split(' ').map(x => parseInt(x, 16));
  return new Uint8Array(arr).buffer;
}

global.Process = {
  findModuleByName(n) {
    return (String(n).toLowerCase() === 'kernel.dll') ? mod : null;
  },
  getModuleByName(n) {
    const m = this.findModuleByName(n);
    if (!m) throw new Error('not found: ' + n);
    return m;
  },
  enumerateModules() { return [mod]; },
  attachModuleObserver(cb) {
    // 模拟"注册观察者时 kernel.dll 已经在进程里" —— 立刻回调 onAdded
    if (cb && typeof cb.onAdded === 'function') {
      try { cb.onAdded(mod); } catch (e) { console.log('!! onAdded: ' + e); }
    }
    return { detach() {} };
  },
  getCurrentThreadId() { return 1; },
  arch: 'ia32',
  pointerSize: 4,
  id: 1234,
};

global.Module = {
  getGlobalExportByName(n) { throw new Error('no exports in stub'); },
  findGlobalExportByName(n) { return null; },
};

global.Memory = {
  alloc() { return new Ptr(0x100000); },
  protect() { return true; },
  scanSync() { return []; },
  readByteArray() { return new ArrayBuffer(8); },
};

global.Interceptor = {
  attach(addr, callbacks) {
    // 记录挂载点，并假装成功
    Interceptor._hits = (Interceptor._hits || []);
    Interceptor._hits.push(addr.sub(mod.base).toInt32());
    return { detach() {} };
  },
  replace() { return true; },
  revert() { return true; },
  flush() {},
  _hits: [],
};

global.Thread = { sleep() {}, backtrace() { return []; } };
global.NativeFunction = function () { this.toString = () => '0x0'; };
global.ObjC = undefined;

// 捕获 log()（hooks.js 里用 console.log + send）
const origLog = console.log;
console.log = (...a) => { logs.push(a.join(' ')); };

// 关键：让 hooks.js 里注册的 setImmediate 真的同步执行
// （hooks.js 靠 setImmediate -> waitKernel -> install 启动）
global.setImmediate = (fn) => { try { fn(); } catch (e) { console.log('!! setImmediate: ' + e); } };

// 执行 hooks.js，然后手动调用 install()
let err = null;
try {
  // hooks.js 是 (function(){...})() 形式，执行后即开始
  eval(src);
} catch (e) {
  err = e;
}
console.log = origLog;

// hooks.js 内部会自动跑；我们检查结果
const hitLog = logs.join('\n');
const rvaTable = (hitLog.match(/使用 RVA 表: ([0-9.]+)/) || [])[1];
const expectTag = '3.0.20.' + (SIZE === 0x2b25000 ? '242' : '237');
const EXPECT_HITS = (SIZE === 0x2b25000) ? 12 : 0;   // 237 场景故意喂 242 字节 → 应全跳过

let fail = 0;
function check(cond, msg) {
  if (cond) { origLog('   OK  ' + msg); }
  else { origLog('   FAIL ' + msg); fail++; }
}

if (err) { origLog('   FAIL eval 抛异常: ' + err.message); fail++; }
origLog('   选表结果: ' + (rvaTable || '(未打印)'));
check(rvaTable === expectTag, '自动选表 = ' + expectTag);

// 检查 hook 是否命中 242 的 12 个地址
const hits = (global.Interceptor._hits || []).slice();
const TABLE = {
  0x2b25000: [0x125f20, 0x2e7e70, 0x2e7a50, 0x2e8800, 0xdd320, 0xdd340,
              0x2f83ae, 0x1b25bd, 0xe52c0, 0x1b3788, 0x1b3a03, 0x28a0f0],
  0x2a3a000: [0x1225f0, 0x2dd200, 0x2dcde0, 0x2ddb90, 0xdb150, 0xdb170,
              0x2ed84e, 0x1aeb6d, 0xe2fb0, 0x1afd38, 0x1affb3, 0x27fee0],
};
const want242 = TABLE[SIZE];
if (!want242) { origLog('   FAIL 未知 SIZE=0x' + SIZE.toString(16)); process.exit(1); }
const got = want242.filter(r => hits.includes(r));
origLog('   hook 命中 ' + got.length + '/12  (总数 ' + hits.length + ')');
check(got.length === EXPECT_HITS, '本表 RVA 命中数 = ' + EXPECT_HITS);

const other = (SIZE === 0x2b25000) ? TABLE[0x2a3a000] : TABLE[0x2b25000];
const wrong = hits.filter(h => other.includes(h));
check(wrong.length === 0, '没有误挂到另一张表的地址（错挂 ' + wrong.length + ' 个）');

// 安装完成行
const doneLine = (hitLog.match(/安装完成：成功 (\d+) 个，跳过 (\d+) 个/) || []);
origLog('   安装结果: ' + (doneLine[0] || '(未打印)'));
check(doneLine[1] === String(EXPECT_HITS) && doneLine[2] === String(12 - EXPECT_HITS),
      EXPECT_HITS + ' 成功 / ' + (12 - EXPECT_HITS) + ' 跳过');

// ── 断言：已加载时不能出现误导性的"等 kernel.dll" ──
check(!/等 kernel\.dll 加载|已注册模块观察者，等 kernel/.test(hitLog),
      'kernel.dll 已加载时不打印"等 kernel.dll"');
check(/已在进程内|模块观察者触发/.test(hitLog),
      '打印了"已在进程内/观察者触发"这类明确状态');

// ── 断言：PATCH_RATE 不能二次 attach 同一地址 ──
const dup = {};
hits.forEach(h => { dup[h] = (dup[h] || 0) + 1; });
const dupAddr = Object.keys(dup).filter(k => dup[k] > 1);
check(dupAddr.length === 0, '同一地址没有被 attach 两次（重复: ' + dupAddr.length + '）');

origLog('\n--- hooks.js 全部日志 ---');
origLog(hitLog.split('\n').map(function(l){return '    | '+l;}).join('\n'));
origLog('--- 日志结束 ---');

origLog(fail === 0 ? '\nHARNESS PASS' : '\nHARNESS FAIL x' + fail);
process.exit(fail === 0 ? 0 : 1);
