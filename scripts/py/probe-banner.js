// probe-banner.js — 게임서버 .11/.12:12000 수동 배너 프로브 (서버가 먼저 말하는지)
'use strict';
const net = require('net');
function probe(ip, port) {
  return new Promise((r) => {
    const s = net.connect(port, ip);
    let got = Buffer.alloc(0);
    const t = setTimeout(() => { s.destroy(); r(ip + ':' + port + ' timeout rx=' + got.length + 'B'); }, 6000);
    s.on('data', (d) => {
      got = Buffer.concat([got, d]);
      if (got.length >= 40) { clearTimeout(t); s.destroy(); r(ip + ':' + port + ' banner ' + got.length + 'B: ' + got.subarray(0, 40).toString('hex')); }
    });
    s.on('error', (e) => { clearTimeout(t); r(ip + ':' + port + ' err ' + e.message); });
    s.on('close', () => { clearTimeout(t); r(ip + ':' + port + ' closed rx=' + got.length + 'B' + (got.length ? ' hex=' + got.toString('hex') : '')); });
  });
}
(async () => {
  console.log(await probe('175.207.21.11', 12000));
  console.log(await probe('175.207.21.12', 12000));
})();
