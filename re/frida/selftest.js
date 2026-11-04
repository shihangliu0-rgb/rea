/*
 * re/frida/selftest.js —— 30 秒验证"Frida 环境到底通不通"
 *
 * 不 hook 任何百度网盘的东西，只做三件事：
 *   1) 打印进程位数与模块数（证明注入成功）
 *   2) 挂一个一定会被调用的系统函数（GetTickCount）计数
 *   3) 尝试找 kernel.dll，找到就报告基址
 *
 * 用法：
 *   python run.py attach --name BaiduNetdisk.exe --script selftest.js
 *   frida -n BaiduNetdisk.exe -l selftest.js
 */
console.log('=== selftest ===');
console.log('PointerSize =', Process.pointerSize * 8, 'bit');
console.log('arch        =', Process.arch);
console.log('modules     =', Process.enumerateModules().length);
console.log('main exe    =', Process.enumerateModules()[0].name,
            '@', Process.enumerateModules()[0].base);

let n = 0;
const p = Module.findExportByName('kernel32.dll', 'GetTickCount');
if (p) {
    Interceptor.attach(p, {
        onLeave: function () {
            if (++n % 200 === 0) console.log('[alive] GetTickCount 已调用', n, '次');
        }
    });
    console.log('[+] 已挂 GetTickCount @', p);
} else {
    console.log('[!] 找不到 GetTickCount —— 说明这个进程不允许 hook');
}

const k = Process.findModuleByName('kernel.dll');
console.log(k ? '[+] kernel.dll @ ' + k.base + ' size=' + k.size
              : '[ ] kernel.dll 尚未加载（开始一个下载后再看）');

setInterval(() => {
    const m = Process.findModuleByName('kernel.dll');
    if (m) console.log('[+] kernel.dll 已加载 @', m.base);
}, 5000);
