// mcp-client.js — minimal MCP stdio client for the REA server.
// Keeps one process alive so the Ghidra session (if any) is reused across calls.
// Usage: node mcp-client.js <commandFile>
//   commandFile: JSON array of {tool, args} executed in order; results printed as JSONL.
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');

const GHIDRA = 'H:\\SA_Analysis\\tools\\ghidra_12.1.4_PUBLIC';
const JAVA = 'H:\\SA_Analysis\\tools\\jdk-21.0.12.1+1';
const env = { ...process.env, GHIDRA_INSTALL_DIR: GHIDRA, JAVA_HOME: JAVA, Path: `${JAVA}\\bin;${process.env.Path}` };

const child = spawn('cmd.exe', ['/c', 'npx', '--yes', 'rea-agents', '--mcp'], {
  env, stdio: ['pipe', 'pipe', 'pipe'], shell: false,
});

let buf = '';
const pending = new Map();
let nextId = 1;

child.stdout.on('data', (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
    }
  }
});
child.stderr.on('data', (d) => process.stderr.write('[mcp-err] ' + d));
child.on('exit', (c) => { process.stderr.write(`[mcp exit ${c}]\n`); process.exit(c || 0); });

function rpc(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}

async function callTool(name, args, timeoutMs) {
  const res = await Promise.race([
    rpc('tools/call', { name, arguments: args }),
    new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout ${name}`)), timeoutMs || 15 * 60 * 1000)),
  ]);
  return res;
}

async function main() {
  const cmdFile = process.argv[2];
  const commands = JSON.parse(fs.readFileSync(cmdFile, 'utf8'));

  const init = await rpc('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'rea-mcp-client', version: '1.0' },
  });
  console.error('[init] ' + JSON.stringify(init.serverInfo));
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

  if (commands[0] && commands[0].tool === '__list__') {
    const tools = await rpc('tools/list', {});
    const want = commands[0].schemas;
    const out = want
      ? tools.tools.filter(t => want.includes(t.name)).map(t => ({ name: t.name, schema: t.inputSchema }))
      : tools.tools.map(t => t.name);
    console.log(JSON.stringify({ tool: '__list__', result: out }, null, 1));
    return;
  }

  for (const c of commands) {
    try {
      const r = await callTool(c.tool, c.args || {}, c.timeoutMs);
      // MCP tool result: { content: [...], isError? }
      const text = (r && r.content) ? r.content.map(x => x.text || '').join('\n') : JSON.stringify(r);
      console.log(JSON.stringify({ tool: c.tool, args: c.args, ok: !(r && r.isError), result: text.length > 400000 ? text.slice(0, 400000) + '...[truncated]' : text }));
    } catch (e) {
      console.log(JSON.stringify({ tool: c.tool, args: c.args, ok: false, error: String(e.message) }));
    }
  }
}

main().then(() => { child.stdin.end(); setTimeout(() => process.exit(0), 1500); })
  .catch(e => { console.error(e); process.exit(1); });
