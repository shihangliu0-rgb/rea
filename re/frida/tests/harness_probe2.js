// 用假 Frida API 跑 probe2.js，验证"完整调用链 + 速率反查 + 桶"逻辑
// 用法： node harness_probe2.js <probe2.js> <size_hex>
const fs = require('fs');

const PROBE = process.argv[2];
const SIZE = parseInt(process.argv[3] || '0x2b25000', 16);
const src = fs.readFileSync(PROBE, 'utf8');

const MODBASE = 0x78100000;
const OTHER_BASE = 0x7b160000;   // netbase.dll
const OTHER_SIZE = 0x200000;
const IS242 = SIZE === 0x2b25000;
const RVA_RATE = IS242 ? 0xdd320 : 0xdb150;
const RVA_CONS = IS242 ? 0xdd340 : 0xdb170;

const logs = [];
const origLog = console.log;
console.log = (...a) => logs.push(a.join(' '));
global.send = () => {};
global.setTimeout = () => 0;
global.setInterval = () => 0;
global.setImmediate = (fn) => { try { fn(); } catch (e) { } };
global.clearInterval = () => {};
global.hexdump = () => '';

// ── 假指针 ────────────────────────────────────────────────────────────────
const BUCKET = { rate: 16384, cap: 16384, tokens: 16384 };
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
Ptr.prototype.readU8 = function () { return 0; };
// 真 Frida 有 readS32；harness 缺了它会让 try/catch 把 +0xb4 静默读成 -1（踩过一次）
Ptr.prototype.readS32 = function () { return this.readU32() | 0; };
Ptr.prototype.writeU32 = function (v) {
  MEM['0x' + this.v.toString(16)] = v >>> 0;
  if (this.v >= LIM_ADDR && this.v < LIM_ADDR + 0x400) {
    LIMOBJ[this.v - LIM_ADDR] = v >>> 0;
  }
  return this;
};
// 桶对象：+0x20 = rate，+8 = cap（这是 kernel.dll 里 TokenBucket 的真实布局）
const BUCKET_ADDR = 0x30a00000;
Ptr.prototype.readU32 = function () {
  const k = '0x' + this.v.toString(16);
  if (MEM[k] !== undefined) return MEM[k] >>> 0;
  if (this.v >= BUCKET_ADDR && this.v < BUCKET_ADDR + 0x100) {
    if (this.v === BUCKET_ADDR + 0x20) return BUCKET.rate;
    if (this.v === BUCKET_ADDR + 8) return BUCKET.cap;
    if (this.v === BUCKET_ADDR + 0x10) return BUCKET.tokens;
  }
  if (this.v >= LIM_ADDR && this.v < LIM_ADDR + 0x400) {
    const off = this.v - LIM_ADDR;
    if (LIMOBJ[off] !== undefined) return LIMOBJ[off] >>> 0;
  }
  return 0;
};
// 限速器对象（0x19fab0 的 this）：+0xb0 限流值, +0xb4 开关, +0xb8 其它, +0x78 内嵌桶
const LIM_ADDR = 0x31a00000;
const LIMOBJ = { 0xb0: 16384, 0xb4: 0, 0xb8: 7 };
const MEM = {};   // '0x地址' -> value，供 writeU32/readU32 用
const SIGBYTES = {};
SIGBYTES[RVA_RATE] = '8b 44 24 04 85 c0';
SIGBYTES[RVA_CONS] = '53 57 56 89 ce';
SIGBYTES[0xdd320] = '8b 44 24 04 85 c0';
SIGBYTES[0xdd340] = '53 57 56 89 ce';
SIGBYTES[0xdb150] = '8b 44 24 04 85 c0';
SIGBYTES[0xdb170] = '53 57 56 89 ce';
SIGBYTES[0x19fab0] = '55 89 e5 53 57 56 81 ec cc 00 00 00';
SIGBYTES[0x19fd30] = '89 c8 8b 4c 24 04 89 88 b4 00 00 00';
SIGBYTES[0x19fd70] = '8b 44 24 04 89 81 b8 00 00 00 c2 04';
Ptr.prototype.readByteArray = function (len) {
  const want = (len === undefined) ? 8 : len;
  const hex = SIGBYTES[this.v - MODBASE];
  if (!hex) return new ArrayBuffer(want);
  const b = new Uint8Array(hex.split(' ').map(x => parseInt(x, 16))).buffer;
  return b.byteLength === want ? b : (b.byteLength > want ? b.slice(0, want) : new ArrayBuffer(want));
};

const mods = [
  { name: 'kernel.dll', path: 'C:\\p\\kernel.dll', base: new Ptr(MODBASE), size: SIZE },
  { name: 'netbase.dll', path: 'C:\\p\\netbase.dll', base: new Ptr(OTHER_BASE), size: OTHER_SIZE },
];
global.Process = {
  findModuleByName(n) { return mods.find(m => m.name.toLowerCase() === String(n).toLowerCase()) || null; },
  getModuleByName(n) { const m = this.findModuleByName(n); if (!m) throw new Error('nf'); return m; },
  findModuleByAddress(a) {
    const v = (a && a.v !== undefined) ? a.v : a;
    for (const m of mods) if (v >= m.base.v && v < m.base.v + m.size) return m;
    return null;
  },
  enumerateModules() { return mods; },
  getCurrentThreadId() { return TID; },
  arch: 'ia32', pointerSize: 4, id: 28804,
};
global.Module = { getGlobalExportByName() { throw new Error('no'); }, findGlobalExportByName() { return null; } };
global.Memory = { alloc: () => new Ptr(0x1000), protect: () => true, scanSync: () => [] };

let NEXT_STACK = [];
let TID = 1000;
global.Backtracer = { ACCURATE: 'accurate', FUZZY: 'fuzzy' };
global.Thread = {
  sleep() { },
  backtrace() { return NEXT_STACK.map(v => new Ptr(v)); },
};

const attached = [];
global.Interceptor = {
  attach(addr, cb) { attached.push({ rva: addr.sub(mods[0].base).toUInt32(), cb }); return { detach() { } }; },
};
global.ptr = (x) => (typeof x === 'object' && x) ? x : new Ptr(x);
global.Date = Date;

// ── 执行 probe2.js ───────────────────────────────────────────────────────
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
  try { fn(); } catch (e) { origLog('   FAIL 抛异常: ' + e.message); fail++; }
  console.log = origLog;
  return logs.join('\n');
}

if (err) { origLog('   FAIL eval 抛异常: ' + err.stack); fail++; }

check(attached.length === (IS242 ? 5 : 2),
      '挂了 ' + (IS242 ? 5 : 2) + ' 个点（242 多挂限速器 3 个 / 237 只有 2 个）' +
      ' [实际 ' + attached.map(a => '0x' + a.rva.toString(16)).join(',') + ']');
const rateHook = attached.find(a => a.rva === RVA_RATE);
const consHook = attached.find(a => a.rva === RVA_CONS);
check(!!rateHook, 'set_rate 地址 = ' + RVA_RATE.toString(16));
check(!!consHook, 'consume 地址 = ' + RVA_CONS.toString(16));

// ── 模拟调用 ─────────────────────────────────────────────────────────────
const BUCKETPTR = new Ptr(BUCKET_ADDR);
function fireSetRate(rate, callerRva, n, chainTail, tid) {
  for (let i = 0; i < n; i++) {
    TID = tid;
    NEXT_STACK = [MODBASE + callerRva].concat(chainTail || [], [OTHER_BASE + 0x1234]);
    rateHook.cb.onEnter.call({
      context: { esp: new Ptr(0x1234), ecx: BUCKETPTR },
      returnAddress: new Ptr(MODBASE + callerRva),
    }, [new Ptr(rate)]);
  }
}
function fireConsume(n, callerRva, tid) {
  for (let i = 0; i < n; i++) {
    TID = tid;
    NEXT_STACK = [MODBASE + callerRva, OTHER_BASE + 0x4321];
    consHook.cb.onEnter.call({
      context: { esp: new Ptr(0x1234), ecx: BUCKETPTR },
      returnAddress: new Ptr(MODBASE + callerRva),
    }, []);
  }
}

if (rateHook && consHook) {
  // 16384 来自 0x2e82c7（calculate_target_speed 内部的 set_rate 调用点）
  fireSetRate(16384, 0x2e82c7, 3, [MODBASE + 0x19fcec, MODBASE + 0xe2f29], 1201);
  // 另一个调用者下发 0x80000（构造期初始速率）
  fireSetRate(0x80000, 0xe32f9, 2, [MODBASE + 0x19fd4c], 1202);
  // 正常速率
  fireSetRate(1006860, 0x2e82c7, 2, [MODBASE + 0x19fcec], 1201);
  BUCKET.rate = 16384; BUCKET.cap = 16384;
  fireConsume(10, 0xdd1e0, 1201);
}

// ── 断言 report() ────────────────────────────────────────────────────────
const out = capture(() => report());
origLog(out.replace(/^/gm, '   | '));
check(/set_rate 共 7 次/.test(out), 'set_rate 总数 = 7（3+2+2）');
check(/consume 共 10 次/.test(out), 'consume 总数 = 10');
check(/16384/.test(out), '速率分布里出现 16384');
check(/524288/.test(out), '速率分布里出现 0x80000 = 524288');
check(/1006860/.test(out), '速率分布里出现 1006860');
check(/0x2e82c7/.test(out), '调用者排行里出现 0x2e82c7');
check(/0xe32f9/.test(out), '调用者排行里出现 0xe32f9');
// 第 3 节：谁下发 16384 + 它的完整链
check(/谁把速率设成 16384/.test(out), '有"谁把速率设成 16384"这一节');
check(/0x2e82c7\s+3/.test(out), '16384 归属 0x2e82c7，3 次');
check(/这个调用者下发过的全部速率/.test(out), '列出了该调用者的全部速率');
check(/kernel\.dll\+0x19fcec/.test(out), '调用链里显示到上一层 kernel frame');
check(/netbase\.dll\+0x1234/.test(out), '调用链保留并标注了非 kernel 模块（不吞掉）');
// 第 4 节：桶
check(/令牌桶（共 1 个/.test(out), '识别出 1 个令牌桶');
check(/rate=16384\s+cap=16384/.test(out), '桶的 rate/cap 都读出来了（+0x20 / +8 布局正确）');
check(/set来自 0x2e82c7/.test(out), '记录到桶的最后一次 set 来源');
// 第 5 节：可粘贴摘要
check(/set_rate callers: /.test(out), '有可粘贴的摘要行');
check(/buckets\s+: /.test(out), '摘要里有桶信息');

// ── why() ────────────────────────────────────────────────────────────────
const w = capture(() => why(16384));
check(/采样到 3 次/.test(w), 'why(16384) 找到 3 次采样');
check(/线程 1201/.test(w), 'why() 显示线程号');
check(/直接调用者 0x2e82c7/.test(w), 'why() 显示直接调用者');
const w0 = capture(() => why(999));
check(/样本里没有这个速率/.test(w0), 'why(不存在的值) 给出明确提示');

// ── chains() ─────────────────────────────────────────────────────────────
const ch = capture(() => chains(20));
check(/调用链样本/.test(ch), 'chains() 可调用');
check(/set_rate\s+rate=16384/.test(ch), 'chains() 里能看到 set_rate rate=16384');

// ── 格式：不能出现 0x0x ──────────────────────────────────────────────────
check(!/0x0x/.test(out + w + ch), '地址格式正确（没有 0x0x）');

// 限速器层：apply / set_enabled / set_x_b8
const LIMPTR = new Ptr(LIM_ADDR);
if (!IS242) {
  // 237 没有限速器表（不猜地址）；只验证"没有这一层时不会炸"
  const l237 = capture(() => report());
  check(/没有命中/.test(l237) || /3.5 限速器/.test(l237), '237：没有限速器表时 report() 不炸');
  origLog(fail === 0 ? 'HARNESS PASS' : 'HARNESS FAIL x' + fail);
  process.exit(fail === 0 ? 0 : 1);
}
const applyHook = attached.find(a => a.rva === 0x19fab0);
const enHook = attached.find(a => a.rva === 0x19fd30);
const b8Hook = attached.find(a => a.rva === 0x19fd70);
check(!!applyHook && !!enHook && !!b8Hook, '限速器 3 个虚函数都挂上了');

function fireApply(n) {
  for (let i = 0; i < n; i++) {
    NEXT_STACK = [MODBASE + 0x2fc866, MODBASE + 0x310b3e];
    applyHook.cb.onEnter.call({
      context: { ecx: LIMPTR },
      returnAddress: new Ptr(MODBASE + 0x2fc866),
    }, []);
  }
}
function fireSetEnabled(on, caller) {
  NEXT_STACK = [MODBASE + caller];
  enHook.cb.onEnter.call({
    context: { ecx: LIMPTR },
    returnAddress: new Ptr(MODBASE + caller),
  }, [new Ptr(on)]);
}
// 用户的真实状态：+0xb4 = -1（不限流）、+0xb0 = 16384
LIMOBJ[0xb4] = -1 | 0; LIMOBJ[0xb0] = 16384; LIMOBJ[0xb8] = 120;
fireApply(5);
fireSetEnabled(-1, 0x23e09a);
const lout = capture(() => report());
check(/3.5 限速器/.test(lout), 'report() 有"3.5 限速器"这一节');
check(/apply 共被调用 5 次/.test(lout), '限速器 apply 计数 = 5');
check(/限流值\(\+0xb0\)=16384/.test(lout), '读到限速器的 +0xb0 = 16384');
check(/开关\(\+0xb4\)=-1/.test(lout), '+0xb4 按有符号读，-1 正常显示');
check(/1 个限速器 = -1（不限流）/.test(lout), '判读出 1 个不限流限速器');
check(/开关=-1\s+对象=/.test(lout), '记录了限流开关被拨动');
check(/全部桶都在地板/.test(lout), '只有地板桶时判读为"全部在地板"');

// 反过来：真在限流的限速器（+0xb4 = 1）
LIMOBJ[0xb4] = 1; LIMOBJ[0xb0] = 122880;
fireApply(2);
const lout2 = capture(() => report());
check(/开关\(\+0xb4\)=1/.test(lout2), '+0xb4 = 1 时显示 1（限流中）');
check(/1 个真在限流/.test(lout2), '判读出 1 个真在限流的限速器');

// ── 真机场景复现：大桶 + 地板桶成对出现，大桶被抽干 ──────────────────────
// 用第二个桶模拟 0x795b3918（rate=524288000 但一直被抽干）
const BUCKET2_ADDR = 0x30b00000;
const B2 = { rate: 524288000, cap: 524288000, tokens: 0 };
const _readU32 = Ptr.prototype.readU32;
Ptr.prototype.readU32 = function () {
  if (this.v >= BUCKET2_ADDR && this.v < BUCKET2_ADDR + 0x100) {
    if (this.v === BUCKET2_ADDR + 0x20) return B2.rate;
    if (this.v === BUCKET2_ADDR + 8) return B2.cap;
    if (this.v === BUCKET2_ADDR + 0x10) return B2.tokens;
  }
  return _readU32.call(this);
};
const B2PTR = new Ptr(BUCKET2_ADDR);
BUCKET.rate = 16384; BUCKET.cap = 16384; BUCKET.tokens = 16384;
B2.rate = 524288000; B2.cap = 524288000; B2.tokens = 0;
for (let i = 0; i < 40; i++) {
  NEXT_STACK = [MODBASE + 0xdd15e];
  consHook.cb.onEnter.call({
    context: { ecx: B2PTR },
    returnAddress: new Ptr(MODBASE + 0xdd15e),
  }, []);
}
const bh = capture(() => report());
check(/4.5 黑洞检测/.test(bh), 'report() 有"4.5 黑洞检测"这一节');
check(/最像瓶颈的桶：0x30b00000/.test(bh), '抽干率最高的桶被指认为瓶颈');
check(/抽干率=100%/.test(bh), '抽干率算对了（40/40）');
check(/consume 合计 50 次/.test(bh), '黑洞检测统计到全部 50 次 consume');
check(!/没有桶的抽干率超过 50%/.test(bh), '有瓶颈时不再说"没有瓶颈"');
check(/全进程令牌桶 consume 合计 50 次，其中 40 次发生在/.test(bh), '抽干次数 = 40');

// ── boost() ──────────────────────────────────────────────────────────────
const bmsg = capture(() => boost());
check(/BOOST 已打开/.test(bmsg), 'boost() 能打开');
check(attached.length === (IS242 ? 5 : 2), 'boost() 没有重新 attach（hook 数不变，避开 e9 跳板坑）');

// 打开后再来 2 次 set_rate(16384)：入参应被改写成 0x1F400000
BUCKET.rate = 16384; BUCKET.cap = 16384;
fireSetRate(16384, 0x2e82c7, 2, [MODBASE + 0x19fcec], 1201);
fireConsume(3, 0xdd1e0, 1201);
const bout = capture(() => report());
check(/\[BOOST 打开\]/.test(bout), 'report() 显示 BOOST 状态');
check(/set_rate 入参 2 次/.test(bout), '统计到改写入参 2 次');
check(/重写桶 3 次/.test(bout), '每次 consume 前重写桶（3 次）');
check(/524288000/.test(bout), '改写后的速率 524288000 出现在报告里');
// boost 打开期间 apply 会写限速器的 +0xb0
fireApply(2);
check(LIMOBJ[0xb0] === 0x1F400000, 'boost() 把限速器的 +0xb0 写成了 0x1F400000');
const bout2 = capture(() => report());
check(/已改写限速器 [1-9]/.test(bout2), 'report() 统计到限速器被改写');
const boff = capture(() => boost(false));
check(/BOOST 已关闭/.test(boff), 'boost(false) 能关');
check(attached.length === (IS242 ? 5 : 2), 'boost(false) 也没有重新 attach');

// ── reset() ──────────────────────────────────────────────────────────────
const r = capture(() => { reset(); report(); });
check(/还没有任何命中/.test(r), 'reset() 之后统计清零');

origLog('');
origLog(fail === 0 ? 'HARNESS PASS' : 'HARNESS FAIL x' + fail);
process.exit(fail === 0 ? 0 : 1);
