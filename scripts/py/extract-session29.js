// extract-session29.js — session29.jsonl (REA MCP 결과) 에서 핵심 항목 추출
import fs from 'fs';
const lines = fs.readFileSync('H:/SA_Analysis/evidence/session29.jsonl', 'utf8').split(/\r?\n/).filter(Boolean);
const want = ['181272bc0', '181273720', '181273700', '1812736e0', '1812736c0', '181273680', '181273650', '181273620', '180d5e6c0', '180333423'];
for (const ln of lines) {
  let o; try { o = JSON.parse(ln); } catch { continue; }
  const s = JSON.stringify(o);
  for (const w of want) {
    if (s.toLowerCase().includes(w)) {
      // result 구조 탐색: o.result 가 문자열이면 그대로, 객체면 normalized_result/items 등 재귀 출력
      console.log(`\n########## 라인 매치: ${w} ##########`);
      const r = o.result ?? o;
      const txt = typeof r === 'string' ? r : (() => {
        try {
          const j = typeof r === 'object' ? (typeof r.normalized_result !== 'undefined' ? r : (typeof r.content !== 'undefined' ? { content: r.content } : r)) : r;
          return JSON.stringify(j, null, 1);
        } catch { return String(r); }
      })();
      console.log(txt.length > 6000 ? txt.slice(0, 6000) + '\n...[truncated]' : txt);
      break; // 라인당 1회만
    }
  }
}
console.log('\n=== 총 라인 수:', lines.length);
