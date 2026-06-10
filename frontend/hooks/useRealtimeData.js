import { useEffect, useState, useRef, useCallback } from "react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/alerts";
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function useRealtimeData() {
  const [events, setEvents] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const socketRef = useRef(null);
  const retriesRef = useRef(0);
  const timerRef = useRef(null);

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

      // On reconnect, fetch recent sessions via REST to resync
      fetch(`${API_URL}/api/sessions?limit=50`)
        .then((r) => r.json())
        .then((data) => {
          if (Array.isArray(data)) {
            setSessions(data);
          }
        })
        .catch(() => {});
    };

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        const d = msg.data || msg;

        // Handle history — new format: { events: [...], sessions: [...] }
        if (msg.type === "history" && msg.data) {
          const historyEvents = Array.isArray(msg.data) ? msg.data : msg.data.events;
          const historySessions = msg.data.sessions;

          if (Array.isArray(historyEvents)) {
            const historyAlerts = historyEvents.map((item, i) => ({
              id: `hist-${item.session_id || i}-${i}`,
              timestamp: item.timestamp,
              severity: item.severity || "LOW",
              type: item.event_type || "unknown",
              ip: item.attacker_ip,
              session_id: item.session_id,
              command: item.raw_command,
              mitreId: item.mitre_technique_id,
            })).reverse();
            setEvents(prev => [...prev, ...historyAlerts].slice(-200));
          }

          if (Array.isArray(historySessions)) {
            setSessions(historySessions);
          }
          return;
        }

        // Handle events
        if (msg.type === "event" || msg.type === "session.closed" || msg.type === "attack_alert") {
          const alert = {
            id: `ws-${Date.now()}-${Math.random()}`,
            timestamp: d.timestamp || new Date().toISOString(),
            severity: d.severity || "INFO",
            type: d.event_type || msg.type,
            ip: d.attacker_ip || d.ip || "unknown",
            session_id: d.session_id,
            command: d.raw_command || d.message,
            mitreId: d.mitre_technique_id || d.attack_type || d.mitre_id,
          };
          setEvents(prev => [...prev, alert].slice(-200));
        }

        // Handle sessions
        if (msg.type === "session.new") {
          setSessions(prev => {
            if (prev.some(s => s.session_id === d.session_id)) return prev;
            return [{ ...d, _new: true }, ...prev].slice(0, 50);
          });
          setTimeout(() => {
            setSessions(prev =>
              prev.map(s => s.session_id === d.session_id ? { ...s, _new: false } : s)
            );
          }, 600);
        }

        if (msg.type === "session.updated") {
          setSessions(prev =>
            prev.map(s =>
              s.session_id === d.session_id ? { ...s, ...d, _updated: true } : s
            )
          );
          setTimeout(() => {
            setSessions(prev =>
              prev.map(s => s.session_id === d.session_id ? { ...s, _updated: false } : s)
            );
          }, 800);
        }

        if (msg.type === "session.closed") {
          const sessionId = d.session_id || msg.session_id;
          if (!sessionId) return;
          setSessions(prev =>
            prev.map(s =>
              s.session_id === sessionId
                ? { ...s, _closing: true, end_time: d.end_time, duration_seconds: d.duration_seconds }
                : s
            )
          );
          setTimeout(() => {
            setSessions(prev => prev.filter(s => s.session_id !== sessionId));
          }, 400);
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
    connect();
    return () => {
      if (socketRef.current) socketRef.current.close();
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [connect]);

  return { events, sessions, connected, reconnecting };
}