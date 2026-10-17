// extract-decomp.js — mcp-client 출력 파일에서 batch_decompile 결과의 의사코드 추출
import fs from 'fs';
const file = process.argv[2];
const outDir = 'H:/SA_Analysis/decompiled';
fs.mkdirSync(outDir, { recursive: true });
const lines = fs.readFileSync(file, 'utf8').split('\n').filter(x => x.trim().startsWith('{'));
for (const line of lines) {
  let j; try { j = JSON.parse(line); } catch { continue; }
  if (j.tool !== 'batch_decompile' || !j.ok) continue;
  const r = JSON.parse(j.result);
  for (const it of (r.normalized_result?.items || [])) {
    const p = it.procedure || {};
    const code = p.decompiled_code || p.pseudocode || '';
    const st = p.status || '?';
    console.log(`${it.address} status=${st} err=${p.error?.code || ''} codeLen=${typeof code === 'string' ? code.length : 0}`);
    if (typeof code === 'string' && code.length) {
      const f = `${outDir}/FUN_${it.address.slice(2)}.c`;
      fs.writeFileSync(f, code, 'utf8');
      console.log(`  → ${f}`);
    }
  }
}
