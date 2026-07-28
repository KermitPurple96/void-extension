#!/usr/bin/env node
/**
 * Void Extension — Sync Server
 * Tiny WebSocket server that relays history between Chrome instances (containers).
 * Run: node void-sync-server.js
 * All Void instances connect to ws://localhost:17580 and share traffic in real-time.
 */
const { WebSocketServer } = require("ws");
const PORT = 17580;

const wss = new WebSocketServer({ port: PORT });
const clients = new Map(); // ws → { name, entries[] }
let allHistory = []; // merged history from all clients

console.log(`[Void Sync] listening on ws://localhost:${PORT}`);

wss.on("connection", (ws) => {
  const info = { name: "unknown", entries: [] };
  clients.set(ws, info);
  console.log(`[Void Sync] client connected (${clients.size} total)`);

  // Send existing merged history to new client
  ws.send(JSON.stringify({ type: "init", entries: allHistory }));

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === "register") {
        info.name = msg.name || "unknown";
        console.log(`[Void Sync] registered: ${info.name}`);
      }

      if (msg.type === "history") {
        // Client sends its history entries
        const entries = (msg.entries || []).map(e => ({
          ...e,
          _logSource: "container",
          _logLabel: info.name,
        }));
        info.entries = entries;

        // Rebuild merged history
        allHistory = [];
        for (const [, c] of clients) {
          allHistory = allHistory.concat(c.entries);
        }

        // Broadcast to all OTHER clients
        const broadcast = JSON.stringify({ type: "update", from: info.name, entries });
        for (const [client] of clients) {
          if (client !== ws && client.readyState === 1) {
            client.send(broadcast);
          }
        }
        console.log(`[Void Sync] ${info.name}: ${entries.length} entries (total: ${allHistory.length})`);
      }
    } catch {}
  });

  ws.on("close", () => {
    clients.delete(ws);
    console.log(`[Void Sync] client disconnected (${clients.size} remaining)`);
  });
});
