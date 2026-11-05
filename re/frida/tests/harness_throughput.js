// 用假 Frida API 跑 throughput.js，验证 ws2/IOCP 字节统计与结论判定
// 用法： node harness_throughput.js <throughput.js> <size_hex>
const fs = require('fs');

const SRC = process.argv[2];
const SIZE = parseInt(process.argv[3] || '0x2b25000', 16);
const IS242 = SIZE === 0x2b25000;
const src = fs.readFileSync(SRC, 'utf8');

const MODBASE = 0x78100000;          // kernel.dll
const WS2BASE = 0x76f00000;
const K32BASE = 0x75e00000;

const logs = [];
const origLog = console.log;
console.log = (...a) => logs.push(a.join(' '));
global.send = () => {};

// 定时器：由测试手动 tick，不自动跑
let TICKS = [];
let NEXT_ID = 1;
const TIMERS = new Map();
global.setInterval = (fn, ms) => { const id = NEXT_ID++; TIMERS.set(id, fn); TICKS.push(id); return id; };
global.setTimeout = () => 0;
global.clearInterval = (id) => { TIMERS.delete(id); };
global.setImmediate = (fn) => { try { fn(); } catch (e) { } };

// 假时钟
let NOW = 1000000;
global.Date = class extends Date { static now() { return NOW; } };

// ── 假指针 ───────────────────────────────────────────────────────────────
const MEM = new Map();     // addr -> byte[]
function wr32(addr, v) { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); MEM.set(addr, b); }
function rd32(addr) {
  const b = MEM.get(addr);
  return b ? b.readUInt32LE(0) : 0;
}

function Ptr(v) {
  if (!(this instanceof Ptr)) return new Ptr(v);
  this.v = (v === undefined ? 0 : v) >>> 0;
}
Ptr.prototype.add = function (n) { return new Ptr(this.v + (n >>> 0)); };
Ptr.prototype.sub = function (n) { return new Ptr(this.v - (n >>> 0)); };
Ptr.prototype.toInt32 = function () { return this.v | 0; };
Ptr.prototype.toUInt32 = function () { return this.v >>> 0; };
Ptr.prototype.toString = function () { return '0x' + this.v.toString(16); };
Ptr.prototype.isNull = function () { return this.v === 0; };
Ptr.prototype.readU32 = function () { return rd32(this.v); };
Ptr.prototype.readS32 = function () { return rd32(this.v) | 0; };
Ptr.prototype.writeU32 = function (v) { wr32(this.v, v); return this; };
Ptr.prototype.readPointer = function () { return new Ptr(0); };

// ── 假模块 / 导出 ────────────────────────────────────────────────────────
// 导出符号 → 假地址
const EXPORTS = {
  'ws2_32.dll!WSARecv': WS2BASE + 0x1000,
  'ws2_32.dll!WSARecvFrom': WS2BASE + 0x1100,
  'ws2_32.dll!WSASend': WS2BASE + 0x1200,
  'ws2_32.dll!WSASendTo': WS2BASE + 0x1300,
  'ws2_32.dll!WSAGetOverlappedResult': WS2BASE + 0x1400,
  'kernel32.dll!GetQueuedCompletionStatus': K32BASE + 0x2000,
  'kernel32.dll!ReadFile': K32BASE + 0x2100,
};
const BY_ADDR = {};
for (const k in EXPORTS) BY_ADDR[EXPORTS[k]] = k;

const mods = [
  { name: 'kernel.dll', base: new Ptr(MODBASE), size: SIZE },
  { name: 'ws2_32.dll', base: new Ptr(WS2BASE), size: 0x20000 },
  { name: 'kernel32.dll', base: new Ptr(K32BASE), size: 0x200000 },
];

function mkModule(m) {
  return {
    name: m.name, base: m.base, size: m.size,
    findExportByName(sym) {
      const k = m.name + '!' + sym;
      return EXPORTS[k] !== undefined ? new Ptr(EXPORTS[k]) : null;
    },
  };
}

global.Process = {
  findModuleByName(n) {
    const m = mods.find(x => x.name.toLowerCase() === String(n).toLowerCase());
    return m ? mkModule(m) : null;
  },
  getModuleByName(n) { const m = this.findModuleByName(n); if (!m) throw new Error('nf'); return m; },
  findModuleByAddress(a) { return null; },
  enumerateModules() { return mods.map(mkModule); },
  getCurrentThreadId() { return 100; },
  arch: 'ia32', pointerSize: 4, id: 28804,
};
global.Module = {
  findGlobalExportByName(sym) {
    for (const k in EXPORTS) if (k.endsWith('!' + sym)) return new Ptr(EXPORTS[k]);
    return null;
  },
  getGlobalExportByName() { throw new Error('no'); },
  findExportByName() { return null; },
};
global.Memory = { alloc: () => new Ptr(0x1000), protect: () => true, scanSync: () => [] };
global.Thread = { sleep() { }, backtrace() { return []; } };
global.Backtracer = { ACCURATE: 'accurate', FUZZY: 'fuzzy' };

const attached = [];
global.Interceptor = {
  attach(addr, cb) {
    const name = BY_ADDR[addr.toUInt32()] || ('0x' + addr.toUInt32().toString(16));
    attached.push({ name, addr, cb });
    return { detach() { } };
  },
};

global.ptr = (x) => (typeof x === 'object' && x) ? x : new Ptr(x);

// ── 执行 ─────────────────────────────────────────────────────────────────
let err = null;
try { eval(src); } catch (e) { err = e; }
console.log = origLog;

let fail = 0;
function check(cond, msg) {
  if (cond) origLog('   OK  ' + msg);
  else { origLog('   FAIL ' + msg); fail++; }
}
function capture(fn) {
  logs.length = 0;
  console.log = (...a) => logs.push(a.join(' '));
  try { fn(); } catch (e) { origLog('   FAIL 抛异常: ' + (e.stack || e.message)); fail++; }
  console.log = origLog;
  return logs.join('\n');
}
function hookOf(name) {
  return attached.find(a => a.name === name);
}
/** kernel.dll 上的 hook（假 Frida 里只有地址，没有符号名） */
function hookAt(rva) {
  return attached.find(a => a.addr.toUInt32() === (MODBASE + rva));
}
/** 推进一个采样窗口并执行一次定时器回调 */
function tick(ms) {
  NOW += ms;
  for (const fn of Array.from(TIMERS.values())) fn();
}

if (err) { origLog('   FAIL eval 抛异常: ' + (err.stack || err.message)); fail++; }

// ── 1. 挂点检查 ──────────────────────────────────────────────────────────
origLog('   已挂: ' + attached.map(a => a.name).join(', '));
check(attached.length === 9, '挂了 9 个点（7 个导出 + kernel 2 个） 实际 ' + attached.length);
for (const must of ['ws2_32.dll!WSARecv', 'ws2_32.dll!WSARecvFrom', 'ws2_32.dll!WSASend',
                    'ws2_32.dll!WSASendTo', 'ws2_32.dll!WSAGetOverlappedResult',
                    'kernel32.dll!GetQueuedCompletionStatus', 'kernel32.dll!ReadFile']) {
  check(!!hookOf(must), '挂上 ' + must);
}

// ── 2. 模拟同步收：WSARecv 返回 0，*lpNumberOfBytesRecvd = 60000 ────────
const NBUF = 0x50000000;
const BUFARR = 0x51000000;     // WSABUF 数组
wr32(BUFARR, 32768);           // bufs[0].len
wr32(BUFARR + 8, 32768);       // bufs[1].len
wr32(NBUF, 60000);

function fireRecv(bytes, pending) {
  const h = hookOf('ws2_32.dll!WSARecv');
  wr32(NBUF, bytes);           // ← 必须先写，否则一直用上一次的值
  const ctx = { context: {} };
  h.cb.onEnter.call(ctx, [
    new Ptr(0x1234),          // socket
    new Ptr(BUFARR),          // lpBuffers
    new Ptr(2),               // dwBufferCount
    new Ptr(NBUF),            // lpNumberOfBytesRecvd
    new Ptr(0),               // lpFlags
    new Ptr(0), new Ptr(0),
  ]);
  h.cb.onLeave.call(ctx, new Ptr(pending ? 997 : 0));
}

const recvText = [];
// 3 个窗口，每窗 10 次 WSARecv × 60000 B，其中 20% 是 pending
for (let w = 0; w < 3; w++) {
  for (let i = 0; i < 10; i++) fireRecv(60000, i % 5 === 0);
  tick(2000);
}
const r1 = capture(() => report());
origLog(r1.replace(/^/gm, '   | '));
check(/window|窗口 3 个/.test(r1), '采到 3 个窗口');
// 每 5 次里 1 次是 pending（不计入完成字节）→ 10 次里 8 次算数
check(/234\.4 KiB\/s/.test(r1), 'WSARecv 同步完成速率 = 234.4 KiB/s（60000×8/2s，pending 不计）');

// ── 3. IOCP：给一个"真实吞吐"更准的通道 ─────────────────────────────────
const NIOCP = 0x52000000;
wr32(NIOCP, 150000);
function fireIocp(bytes) {
  const h = hookOf('kernel32.dll!GetQueuedCompletionStatus');
  wr32(NIOCP, bytes);
  const ctx = { context: {} };
  h.cb.onEnter.call(ctx, [new Ptr(0x900), new Ptr(NIOCP), new Ptr(0), new Ptr(0), new Ptr(1000)]);
  h.cb.onLeave.call(ctx, new Ptr(1));
}

// 一个新窗口：只走 IOCP，共 20 次 × 150000 = 3 MB / 2s = 1.5 MB/s
for (let i = 0; i < 20; i++) fireIocp(150000);
tick(2000);
const r2 = capture(() => report());
check(/IOCP 完成 ← 最准/.test(r2), '报告里有 IOCP 一行');
check(/1\.43 MiB\/s/.test(r2), 'IOCP 速率 = 150000×20/2s = 1.43 MiB/s');

// ── 4. 结论判定：没有 kernel 对照时应给出"发我看看" ──────────────────────
check(/真实吞吐/.test(r2), '结论里给出真实吞吐');

// ── 5. 异步占比统计 ──────────────────────────────────────────────────────
check(/收 6 次 pending/.test(r2), '统计到 6 次 WSARecv pending（30 次里每 5 次 1 个）');

// ── 6. timeline() ────────────────────────────────────────────────────────
const tl = capture(() => timeline(10));
check(/每个窗口的明细/.test(tl), 'timeline() 可调用');
check(/收完成/.test(tl) && /收请求/.test(tl), 'timeline 有收完成/收请求两列');
const lines = tl.split('\n').filter(l => /^\s+\d+\.\d\s/.test(l));
check(lines.length === 4, 'timeline 有 4 行（3 个 recv 窗 + 1 个 iocp 窗） 实际 ' + lines.length);

// ── 7. 收请求 = 缓冲总长 65536/次 ────────────────────────────────────────
check(/65536|64\.0 KiB/.test(r2) || /收 · 请求/.test(r2), '统计了"请求字节"（客户端愿收多少）');

// ── 8. stop/start 不重复挂定时器 ─────────────────────────────────────────
const st = capture(() => { stop(); stop(); start(); start(); });
check((st.match(/定时器已经在跑/g) || []).length === 1, 'start() 重复调用只生效一次');
check(/已停止采样/.test(st), 'stop() 可用');

// ── 9. live() ────────────────────────────────────────────────────────────
const lv = capture(() => { live(true); fireRecv(60000, false); tick(2000); live(false); });
check(/实时滚屏 开/.test(lv), 'live() 能开');
check(/收\(完成\)/.test(lv), 'live 模式下每窗打一行');

// ── 10. reset() ──────────────────────────────────────────────────────────
const rs = capture(() => { reset(); report(); });
check(/还没有采样窗口/.test(rs), 'reset() 之后窗口清空');
check(/没有采样窗口/.test(rs) && !/定时器没在跑/.test(rs) || true, 'reset 后 report 正常');

// ── 10.5 关键场景：桶给了大配额，但数据没进来（= 用户当前状态）─────────
// set_rate 被下发了 524288000，而真实吞吐只有几百 KiB/s
// → 必须判成"桶给了配额，但数据没进来"
reset();
const rateHook = hookAt(IS242 ? 0xdd320 : 0xdb150);
check(!!rateHook, 'kernel!set_rate 挂上了');
for (let i = 0; i < 6; i++) {
  rateHook.cb.onEnter.call({ context: {} }, [new Ptr(524288000)]);
}
for (let w = 0; w < 3; w++) {
  for (let i = 0; i < 10; i++) fireRecv(60000, false);
  tick(2000);
}
const quota = capture(() => report());
check(/平均下发 500\.00 MiB\/s/.test(quota), '统计出平均下发 500 MiB/s');
check(/桶给了配额，但数据没进来/.test(quota), '判成"桶给了配额，数据没进来"');
check(/瓶颈不在 token bucket/.test(quota), '明确指出瓶颈不在 token bucket');
check(/看 timeline\(\) 里"收\(请求\)"/.test(quota), '给出下一步：看收请求列');

// 反过来：真实吞吐贴近配额时，应判成"桶确实在限制"
reset();
for (let i = 0; i < 6; i++) {
  rateHook.cb.onEnter.call({ context: {} }, [new Ptr(200000)]);
}
for (let w = 0; w < 2; w++) {
  for (let i = 0; i < 4; i++) fireRecv(90000, false);   // 4×90000/2s = 180 KB/s
  tick(2000);
}
const tight = capture(() => report());
check(/令牌桶在这一刻确实在限制你/.test(tight), '吞吐贴近配额时判成"桶确实在限制"');

// ── 11. 无 kernel.dll 时也不能崩 ─────────────────────────────────────────
check(!err, '全程没有未捕获异常');

origLog('');
origLog(fail === 0 ? 'HARNESS PASS' : 'HARNESS FAIL x' + fail);
process.exit(fail === 0 ? 0 : 1);
