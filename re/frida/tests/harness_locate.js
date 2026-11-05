// 用假的 Frida API 跑 locate.py 生成的 agent，验证逻辑（不只是语法）
const fs = require('fs');
const body = fs.readFileSync(process.argv[2], 'utf8');

const MODBASE = 0x78100000;
const MODSIZE = 43 * 1024 * 1024 + 0x10000;   // 43.1MB，模拟用户的版本
const buf = Buffer.alloc(MODSIZE, 0x90);
const put = (off, pat) => {
  const b = Buffer.from(pat.split(' ').map(x => parseInt(x, 16)));
  b.copy(buf, off);
};
put(0x123456, '55 89 e5 53 57 56 83 ec 2c');
put(0x200000, '55 89 e5 53 57 56 83 ec 2c');   // set_param 两个候选
put(0x2a00000, '8b 44 24 04 85 c0');
put(0x2b00000, '53 57 56 89 ce');

function Ptr(v) {
  if (!(this instanceof Ptr)) return new Ptr(v);
  this.v = v >>> 0;
}
Ptr.prototype.add = function (n) { return new Ptr((this.v + (n >>> 0)) >>> 0); };
Ptr.prototype.sub = function (n) { return new Ptr((this.v - (n >>> 0)) >>> 0); };
Ptr.prototype.toInt32 = function () { return this.v | 0; };
Ptr.prototype.toString = function () { return '0x' + this.v.toString(16); };
Ptr.prototype.compare = function (o) { return this.v === o.v ? 0 : (this.v < o.v ? -1 : 1); };

const sends = [];
global.send = (o) => sends.push(o);
global.hexdump = () => '78100000  55 89 e5 53 57 56 83 ec 2c';

const modules = [
  { name: 'kernel.dll', path: 'C:\\p\\kernel.dll', base: new Ptr(MODBASE), size: MODSIZE },
  { name: 'netbase.dll', path: 'C:\\p\\netbase.dll', base: new Ptr(0x4fd0000), size: 12 * 1024 * 1024 },
];
global.Process = {
  findModuleByName(n) {
    return modules.find(m => m.name.toLowerCase() === String(n).toLowerCase()) || null;
  },
  enumerateModules() { return modules; },
};
// ★ 模拟真机：Frida 的 Memory.scanSync 对超大的 range 会抛异常
//   （用户实测：整段 43MB 一次扫 → 每页都被拒 → 命中全 0）
const MAX_RANGE = 1 * 1024 * 1024;
global.Memory = {
  scanSync(addr, size, pat) {
    if (size > MAX_RANGE) {
      throw new Error('invalid argument');
    }
    const needle = Buffer.from(pat.split(' ').map(x => parseInt(x, 16)));
    const start = addr.v - MODBASE;
    const end = Math.min(MODSIZE, start + (size >>> 0));
    const out = [];
    let i = buf.indexOf(needle, start);
    while (i >= 0 && i + needle.length <= end) {
      out.push({ address: new Ptr(MODBASE + i) });
      i = buf.indexOf(needle, i + 1);
    }
    return out;
  },
};

eval(body);

const head = sends.find(s => s.type === 'head');
const pts = sends.filter(s => s.type === 'point');
const done = sends.some(s => s.type === 'done');
const prog = sends.filter(s => s.type === 'progress').length;

console.log('head      :', head ? head.name + ' size=0x' + head.size.toString(16) : 'MISSING');
console.log('point 数量:', pts.length);
console.log('done      :', done);
console.log('progress  :', prog, '次心跳');
const refused = pts.filter(p => p.refuse > 0).length;
console.log('被拒页数   :', refused, '个点位有被拒（应为 0）');
for (const p of pts) {
  const near = p.hits.length
    ? p.hits.map(h => Math.abs(h.rva - p.old)).reduce((a, b) => Math.min(a, b), Infinity)
    : null;
  console.log('  %s  hits=%d  %s', p.name.padEnd(26), p.hits.length,
              near === null ? 'MISS' : 'closest=0x' + near.toString(16));
}
const sp = pts.find(p => p.name === 'set_param');
console.log('\nset_param 候选:', sp.hits.map(h => '0x' + h.rva.toString(16) + ' [' + h.before + ']'));

let fail = 0;
if (!done) { console.log('!! 没收到 done'); fail++; }
if (pts.length !== 12) { console.log('!! point 数量应为 12'); fail++; }
if (sp.hits.length !== 2) { console.log('!! set_param 候选数应为 2'); fail++; }
if (!sp.hits[0].before) { console.log('!! before 字节没带上'); fail++; }
if (head.size !== MODSIZE) { console.log('!! size 不对'); fail++; }
if (refused > 0) { console.log('!! 有页被拒绝，扫描分页逻辑没生效'); fail++; }
if (sp.hits.length !== 2) { console.log('!! set_param 候选数应为 2'); fail++; }
const rate = pts.find(p => p.name === 'bucket.set_rate');
if (!rate.hits.length) { console.log('!! bucket.set_rate 应该找到 1 个'); fail++; }
console.log(fail === 0 ? '\nHARNESS PASS' : '\nHARNESS FAIL x' + fail);
process.exit(fail === 0 ? 0 : 1);
