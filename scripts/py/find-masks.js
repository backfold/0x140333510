// find-masks.js — packets.log(원문)/decoded.log에서 마스크 바이트 등장 위치 검색
import fs from 'fs';
const M_c2s = Buffer.from('85a3520d83db99b93ae96247c74f7c03', 'hex');
const M_s2c = Buffer.from('f2596446d34b7b6469cc4ef7ca42dc46', 'hex');
for (const f of ['H:/SA_Analysis/logs/run1/packets.log', 'H:/SA_Analysis/logs/run1/decoded.log']) {
  let data;
  try { data = fs.readFileSync(f, 'latin1'); } catch { console.log(`${f}: 없음`); continue; }
  console.log(`\n=== ${f} (${(data.length / 1048576).toFixed(1)}MB, 텍스트 모드) ===`);
  for (const [name, m] of [['M_c2s', M_c2s], ['M_s2c', M_s2c]]) {
    // 원문 bin이면 hex로 2바이트 문자열 검색, 로그 텍스트면 '85 a3' 형태와 연속 hex 형태 둘 다
    for (const pat of [m.toString('latin1'), [...m].map(b => b.toString(16).padStart(2, '0')).join(' '), m.toString('hex')]) {
      let idx = 0, n = 0;
      while ((idx = data.indexOf(pat, idx)) !== -1 && n < 5) {
        const lineStart = data.lastIndexOf('\n', idx) + 1;
        console.log(`  ${name} pat[${pat.length > 6 ? 'hexrow' : 'raw'}] @${idx}: ${data.slice(lineStart, lineStart + 80).replace(/\n/g, ' ')}`);
        idx += 1; n++;
      }
      if (n) break;
    }
    if (!n) console.log(`  ${name}: 없음`);
  }
}
