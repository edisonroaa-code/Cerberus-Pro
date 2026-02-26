import { WebSocketServer } from 'ws';

// Keep env naming consistent with the rest of the tooling (agent-runner uses AGENT_RUNNER_PORT).
const PORT = process.env.WS_BRIDGE_PORT ? parseInt(process.env.WS_BRIDGE_PORT) : 8000;

const wss = new WebSocketServer({ port: PORT, path: '/ws' });

const clients = new Set();

console.log(`WebSocket bridge listening on ws://localhost:${PORT}/ws`);

wss.on('connection', (ws, req) => {
  console.log('Client connected', req.socket.remoteAddress);
  clients.add(ws);

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (e) {
      console.warn('Received non-json message, ignoring');
      return;
    }

    // Relay logic:
    // - If UI sends { action: 'start' } broadcast to all other clients (agents)
    // - If agent sends { type: 'log' } broadcast to all other clients (UIs)

    if (msg.action === 'start' || msg.action === 'stop' || msg.action === 'status') {
      // Broadcast to others (likely agents)
      for (const c of clients) {
        if (c !== ws && c.readyState === c.OPEN) c.send(JSON.stringify(msg));
      }
    } else if (msg.type === 'log' || msg.type === 'status') {
      // Broadcast log/status messages to UI clients
      for (const c of clients) {
        if (c !== ws && c.readyState === c.OPEN) c.send(JSON.stringify(msg));
      }
    } else if (msg.type === 'register') {
      // simple register message can be ignored (keeps future compatibility)
      console.log('Register:', msg.role || 'unknown');
    } else {
      // Generic broadcast for unknown messages (safe default)
      for (const c of clients) {
        if (c !== ws && c.readyState === c.OPEN) c.send(JSON.stringify(msg));
      }
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
    console.log('Client disconnected');
  });

  ws.on('error', (err) => {
    console.error('WS error', err);
  });
});

process.on('SIGINT', () => {
  console.log('Shutting down websocket bridge');
  wss.close(() => process.exit(0));
});
