import net from 'node:net';
import fs from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';

function envInt(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function loadEnvFile(filePath = '.env') {
  if (!fs.existsSync(filePath)) return;
  const content = fs.readFileSync(filePath, 'utf8');
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (!key) continue;
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

async function isListening(port, host = '127.0.0.1', timeoutMs = 350) {
  return await new Promise((resolve) => {
    const socket = new net.Socket();
    const done = (value) => {
      try { socket.destroy(); } catch {}
      resolve(value);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

function killTree(pid) {
  if (!pid) return;
  // Best-effort on Windows: kill the whole process tree.
  spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
}

function spawnTask(name, command, args, extraEnv = {}) {
  const child = spawn(command, args, {
    shell: true,
    stdio: 'inherit',
    env: { ...process.env, ...extraEnv },
  });
  child.__taskName = name;
  return child;
}

async function main() {
  loadEnvFile('.env');

  const apiPort = envInt('API_PORT', 8011);
  const wsBridgePort = envInt('WS_BRIDGE_PORT', 8000);
  const agentPort = envInt('AGENT_RUNNER_PORT', 3001);
  const frontendPort = envInt('VITE_DEV_PORT', 5173);

  const tasks = [];

  const frontendUp = await isListening(frontendPort);
  if (frontendUp) {
    console.log(`[dev-all] FRONTEND already listening on http://127.0.0.1:${frontendPort} (skipping start)`);
  } else {
    tasks.push(spawnTask('FRONTEND', 'npm', ['run', 'dev']));
    // Give vite a moment to bind so logs don't interleave too early.
    await sleep(250);
  }

  const backendUp = await isListening(apiPort);
  if (backendUp) {
    console.log(`[dev-all] BACKEND already listening on http://127.0.0.1:${apiPort} (skipping start)`);
  } else {
    tasks.push(
      spawnTask(
        'BACKEND',
        '.venv\\Scripts\\python.exe',
        [
          '-m',
          'uvicorn',
          'backend.ares_api:app',
          '--host',
          '127.0.0.1',
          '--port',
          String(apiPort),
          '--reload',
          '--reload-exclude',
          'backend/history',
        ],
        { ENVIRONMENT: process.env.ENVIRONMENT || 'development' }
      )
    );
    await sleep(250);
  }

  const wsBridgeUp = await isListening(wsBridgePort, '127.0.0.1');
  if (wsBridgeUp) {
    console.log(`[dev-all] WS bridge already listening on ws://localhost:${wsBridgePort}/ws (skipping start)`);
  } else {
    tasks.push(spawnTask('WS', 'npm', ['run', 'ws-bridge'], { WS_BRIDGE_PORT: String(wsBridgePort) }));
    await sleep(150);
  }

  const agentUp = await isListening(agentPort);
  if (agentUp) {
    console.log(`[dev-all] AGENT runner already listening on http://localhost:${agentPort} (skipping start)`);
  } else {
    tasks.push(
      spawnTask('AGENT', 'npm', ['run', 'agent-runner'], {
        AGENT_RUNNER_PORT: String(agentPort),
        BRIDGE_WS: process.env.BRIDGE_WS || `ws://localhost:${wsBridgePort}/ws`,
      })
    );
  }

  const shutdown = () => {
    // Kill in reverse order (agent/ws/backend/frontend).
    for (let i = tasks.length - 1; i >= 0; i--) {
      const t = tasks[i];
      try {
        killTree(t.pid);
      } catch {}
    }
  };

  process.on('SIGINT', () => {
    shutdown();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    shutdown();
    process.exit(0);
  });

  // If any spawned task exits, stop the rest (fail-fast is still desirable during dev).
  for (const t of tasks) {
    t.on('exit', (code) => {
      if (code && code !== 0) {
        console.error(`[dev-all] ${t.__taskName || 'task'} exited with code=${code}. Shutting down others.`);
        shutdown();
        process.exit(code);
      }
    });
  }
}

main().catch((e) => {
  console.error('[dev-all] fatal:', e);
  process.exit(1);
});
