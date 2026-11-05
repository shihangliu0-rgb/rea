
(function () {
  var cfg = [{"name": "set_param", "rva": 1189360, "pat": "55 89 e5 53 57 56 83 ec 2c"}, {"name": "update_max_speed", "rva": 3002880, "pat": "55 89 e5 53 57 56 83 e4 f8"}, {"name": "set_restrict_ratio", "rva": 3001824, "pat": "55 89 e5 53 57 56 81 ec"}, {"name": "calculate_target_speed", "rva": 3005328, "pat": "55 89 e5 53 57 56 83 e4 f8"}, {"name": "bucket.set_rate", "rva": 897360, "pat": "8b 44 24 04 85 c0"}, {"name": "bucket.consume", "rva": 897392, "pat": "53 57 56 89 ce"}, {"name": "cdn_speed_limit_dispatch", "rva": 3070030, "pat": "8b 0b e8"}, {"name": "close_cdn(decided)", "rva": 1764205, "pat": "8b 7d d0 0f af ce"}, {"name": "set_try_speedup_flag", "rva": 929712, "pat": "55 89 e5 53 57 56 81 ec"}, {"name": "block_gate(pre)", "rva": 1768760, "pat": "29 d8 89 86 f0 00 00 00"}, {"name": "download_threshold", "rva": 1769395, "pat": "f2 0f 59 0d"}, {"name": "set_download_restrict_ratio", "rva": 2621152, "pat": "55 89 e5 53 57 56 81 ec"}];        // [{name, rva, pat, desc}]
  var modName = "kernel.dll"; // 'kernel.dll'
  var limit = 400;

  var mod = null;
  try { mod = Process.findModuleByName(modName); } catch (e) {}
  if (!mod) {
    send({ type: 'no_module', want: modName,
           have: Process.enumerateModules().map(function (m) { return m.name; }) });
    return;
  }

  var info = { type: 'head', name: mod.name, path: mod.path,
               base: mod.base.toString(), size: mod.size,
               baseAddr: mod.base };
  send(info);

  var start = mod.base;
  var modSize = mod.size;
  var PAGE = 0x10000;              // 64KB 一页：Frida 的 range 上限很小，不能一次扫 43MB

  for (var i = 0; i < cfg.length; i++) {
    var p = cfg[i];
    var hits = [];
    var refuse = 0;                // 被拒绝的页数
    var scannedBytes = 0;
    var nextBeat = 8 * 1024 * 1024;

    for (var off = 0; off < modSize && hits.length < limit; off += PAGE) {
      var len = Math.min(PAGE, modSize - off);
      var base0 = start.add(off);
      var found;
      try {
        found = Memory.scanSync(base0, len, p.pat);
      } catch (e) {
        refuse++;
        scannedBytes += len;
        continue;
      }
      if (found && found.length) {
        for (var q = 0; q < found.length && hits.length < limit; q++) {
          var rva = found[q].address.sub(mod.base).toInt32();
          var before = '';
          try {
            var back = found[q].address.sub(8);
            if (back.compare(mod.base) >= 0) {
              before = hexdump(back, { length: 8, header: false, ansi: false });
              before = before.split('\n')[0].replace(/^[0-9a-f]+\s+/, '').trim();
            }
          } catch (e2) { before = '?'; }
          hits.push({ rva: rva, before: before });
        }
      }
      scannedBytes += len;
      if (scannedBytes >= nextBeat) {
        send({ type: 'progress', name: p.name, rva: scannedBytes, size: modSize });
        nextBeat += 8 * 1024 * 1024;
      }
    }

    send({ type: 'point', name: p.name, old: p.rva, hits: hits,
           desc: p.desc, refuse: refuse,
           pages: Math.ceil(modSize / PAGE) });
  }
  send({ type: 'done' });
})();
