#!/usr/bin/env node
const express = require('express');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const readline = require('readline');
const path = require('path');

const PORT = process.env.AGENT_RUNNER_PORT ? parseInt(process.env.AGENT_RUNNER_PORT) : 3001;
const BRIDGE_WS = process.env.BRIDGE_WS || 'ws://localhost:8000/ws';
const AGENT_SCRIPT = path.join(__dirname, '..', 'agent_cerberus_sqlmap.py');
const CERBERUS_ENGINE_PATH = path.join(__dirname, '..', '..', 'cerberus_engine', 'sqlmap.py');

const app = express();
app.use(express.json());

let childProcess = null;
let wsClient = null;
let wsReady = false;
let logBuffer = [];

function connectBridge() {
  if (wsClient && (wsClient.readyState === wsClient.OPEN || wsClient.readyState === wsClient.CONNECTING)) return;
  wsClient = new WebSocket(BRIDGE_WS);

  wsClient.on('open', () => {
    wsReady = true;
    // register runner
    try { wsClient.send(JSON.stringify({ type: 'register', role: 'runner' })); } catch (e) {}
    // flush buffered logs
    for (const msg of logBuffer) {
      try { wsClient.send(msg); } catch (e) {}
    }
    logBuffer = [];
    console.log('Connected to bridge', BRIDGE_WS);
  });

  wsClient.on('close', () => { wsReady = false; console.log('Bridge connection closed'); setTimeout(connectBridge, 2000); });
  wsClient.on('error', (err) => { wsReady = false; /* silent */ });
}

function sendLogToBridge(obj) {
  const payload = JSON.stringify(obj);
  if (wsReady && wsClient && wsClient.readyState === wsClient.OPEN) {
    try { wsClient.send(payload); } catch (e) { logBuffer.push(payload); }
  } else {
    logBuffer.push(payload);
  }
}

app.post('/start', (req, res) => {
  if (childProcess) return res.status(409).json({ ok: false, msg: 'Agent already running' });

  // spawn python agent script
  const python = process.env.PYTHON_CMD || 'python';
  childProcess = spawn(python, [AGENT_SCRIPT], { cwd: process.cwd(), env: process.env });

  const rl = readline.createInterface({ input: childProcess.stdout });
  rl.on('line', (line) => {
    const trimmed = line.toString();
    // forward to bridge
    sendLogToBridge({ type: 'log', component: 'AGENT', level: 'INFO', msg: trimmed });
    // also send SQLMAP-labeled logs if line looks like SQLMap output
    // Map legacy mentions to Cerberus Pro
    if (trimmed.toLowerCase().includes('sqlmap') || trimmed.toLowerCase().includes('cerberus')) {
      sendLogToBridge({ type: 'log', component: 'CERBERUS_PRO', level: 'INFO', msg: trimmed });
    }
    process.stdout.write(`[AGENT] ${trimmed}\n`);
  });

  childProcess.stderr.on('data', (d) => {
    const txt = d.toString();
    sendLogToBridge({ type: 'log', component: 'AGENT', level: 'ERROR', msg: txt });
    process.stderr.write(`[AGENT-ERR] ${txt}`);
  });

  childProcess.on('exit', (code, sig) => {
    sendLogToBridge({ type: 'log', component: 'AGENT', level: 'WARN', msg: `agent exited code=${code} sig=${sig}` });
    childProcess = null;
  });

  res.json({ ok: true, msg: 'agent started' });
});

app.post('/stop', async (req, res) => {
  if (!childProcess) return res.status(409).json({ ok: false, msg: 'No agent running' });

  try {
    childProcess.kill('SIGTERM');
    // wait up to 3s
    const timeout = setTimeout(() => {
      if (childProcess) {
        try { childProcess.kill('SIGKILL'); } catch (e) {}
      }
    }, 3000);

    childProcess.on('exit', () => { clearTimeout(timeout); childProcess = null; });
    res.json({ ok: true, msg: 'stopping' });
  } catch (e) {
    res.status(500).json({ ok: false, msg: 'failed to stop', error: String(e) });
  }
});

app.get('/status', (req, res) => {
  res.json({ running: !!childProcess, pid: childProcess ? childProcess.pid : null });
});

app.listen(PORT, () => {
  console.log(`Agent Runner HTTP API listening on http://localhost:${PORT}`);
  connectBridge();
});
