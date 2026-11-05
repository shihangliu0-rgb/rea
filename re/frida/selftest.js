/*
 * re/frida/selftest.js —— 30 秒验证"Frida 环境到底通不通"
 * 兼容 Frida 16.x / 17.x（17 删除了 Module.findExportByName 等静态 API）
 *
 * 用法：
 *   frida -n BaiduNetdisk.exe -l selftest.js
 *   python re/frida/run.py attach --name BaiduNetdisk.exe --script selftest.js
 */
function log(s) {
    console.log(s);
    try { send({ tag: 'log', text: s }); } catch (e) { }
}

function getModule(name) {
    try {
        if (Process.findModuleByName) return Process.findModuleByName(name);
        return Process.getModuleByName(name);
    } catch (e) { return null; }
}

function findExport(modName, symName) {
    var m = getModule(modName);
    if (m && m.findExportByName) {
        try { var p = m.findExportByName(symName); if (p) return p; } catch (e) { }
    }
    if (Module.findExportByName) {
        try { var q = Module.findExportByName(modName, symName); if (q) return q; } catch (e) { }
    }
    var g = Module.findGlobalExportByName || Module.getGlobalExportByName;
    if (g) { try { var r = g(symName); if (r) return r; } catch (e) { } }
    return null;
}

log('=== selftest ===');
log('PointerSize = ' + Process.pointerSize * 8 + ' bit');
log('arch        = ' + Process.arch);
log('pid         = ' + Process.id);

var mods = null;
try {
    mods = Process.enumerateModules();
    log('modules     = ' + mods.length);
    log('main exe    = ' + mods[0].name + ' @ ' + mods[0].base);
} catch (e) {
    log('[i] enumerateModules 不可用，改用 findModuleByName 探测：' + e);
}

var n = 0;
var p = findExport('kernel32.dll', 'GetTickCount');
if (p) {
    Interceptor.attach(p, {
        onLeave: function () {
            if (++n % 500 === 0) log('[alive] GetTickCount 已调用 ' + n + ' 次');
        }
    });
    log('[+] 已挂 GetTickCount @ ' + p + '  → 说明本进程允许 hook');
} else {
    log('[!] 找不到 GetTickCount —— 这个进程可能不允许 hook');
}

var k = getModule('kernel.dll');
log(k ? '[+] kernel.dll @ ' + k.base + ' size=' + k.size
      : '[ ] kernel.dll 尚未加载（在客户端里点一个下载后再看）');

var reported = false;
setInterval(function () {
    var m = getModule('kernel.dll');
    if (m && !reported) {
        reported = true;
        log('[+] kernel.dll 已加载 @ ' + m.base);
        // 顺手验证一下关键 RVA 的字节（版本对不对）
        try {
            var sig = m.base.add(0xe2fb0);
            log('    RVA 0xe2fb0 前 8 字节 = ' + sig.readByteArray(8));
        } catch (e) { }
    }
}, 3000);
