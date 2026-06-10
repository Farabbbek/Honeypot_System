import { useEffect, useRef, useCallback, useState } from "react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/alerts";
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function useWebSocket(demoMode = false) {
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const socketRef = useRef(null);
  const retriesRef = useRef(0);
  const timerRef = useRef(null);
  const handlersRef = useRef(new Map());
  const demoIntervalRef = useRef(null);

  const getBackoff = useCallback(() => {
    const backoff = Math.min(30, Math.pow(2, retriesRef.current));
    retriesRef.current++;
    return backoff * 1000;
  }, []);

  const connect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.close();
    }

    const socket = new WebSocket(WS_URL);
    socketRef.current = socket;

    socket.onopen = () => {
      setConnected(true);
      setReconnecting(false);
      retriesRef.current = 0;
    };

    socket.onclose = () => {
      setConnected(false);
      setReconnecting(true);
      const delay = getBackoff();
      timerRef.current = setTimeout(connect, delay);

      // On reconnect, fetch last 50 events via REST to resync
      fetch(`${API_URL}/api/alerts?limit=50`)
        .then((r) => r.json())
        .then((data) => {
          if (Array.isArray(data) && handlersRef.current.has("history")) {
            handlersRef.current.get("history")({ data });
          }
        })
        .catch(() => {});
    };

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        const type = msg.type || msg.event_type || "event";
        const handler = handlersRef.current.get(type);
        if (handler) {
          handler(msg);
        }
        // Also dispatch to "all" handlers for universal listeners
        const allHandler = handlersRef.current.get("*");
        if (allHandler) {
          allHandler(msg);
        }
      } catch (err) {
        console.error("WS Parse Error", err);
      }
    };

    socket.onerror = () => {
      socket.close();
    };
  }, [getBackoff]);

  useEffect(() => {
    if (demoMode) {
      let counter = 0;
      demoIntervalRef.current = setInterval(() => {
        counter++;
        const demoAlert = generateDemoAlert(counter);
        handlersRef.current.forEach((handler, type) => {
          if (type === "event" || type === "*") {
            handler(demoAlert);
          }
        });
      }, 2000 + Math.random() * 3000);
      setConnected(true);
      return () => clearInterval(demoIntervalRef.current);
    }

    connect();
    return () => {
      if (socketRef.current) socketRef.current.close();
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [connect, demoMode]);

  const subscribe = useCallback((type, handler) => {
    handlersRef.current.set(type, handler);
    return () => handlersRef.current.delete(type);
  }, []);

  return { connected, reconnecting, subscribe };
}

function generateDemoAlert(id) {
  const types = ["cowrie.login.failed", "cowrie.command.input", "cowrie.session.connect"];
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const ips = ["185.220.101.42", "91.219.236.166", "45.142.212.100", "103.253.145.28"];
  const type = types[Math.floor(Math.random() * types.length)];
  const severity = severities[Math.floor(Math.random() * severities.length)];
  const ip = ips[Math.floor(Math.random() * ips.length)];

  return {
    id: `demo-${id}`,
    timestamp: new Date().toISOString(),
    severity,
    type,
    ip,
    session_id: `sess-${Math.random().toString(36).slice(2, 10)}`,
    command: type.includes("command.input") ? "cat /etc/passwd" : null,
  };
}