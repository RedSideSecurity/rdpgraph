"""Aggregate normalized RDP events into a vis-network graph payload."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable


def _count_by_id(events: list[dict]) -> dict:
    out: dict[int, int] = {}
    for e in events:
        eid = e.get("event_id")
        if eid is None:
            continue
        out[eid] = out.get(eid, 0) + 1
    return dict(sorted(out.items()))


def _host_label(ip: str, hostname: str) -> str:
    """Prefer hostname when known, fall back to IP, fall back to 'unknown'."""
    if hostname and ip:
        return f"{hostname} ({ip})"
    return hostname or ip or "unknown"


def _host_key(ip: str, hostname: str) -> str:
    """Stable id for a host node. Hostname wins because IPs change."""
    return (hostname or ip or "unknown").lower()


def build_graph(events: Iterable[dict]) -> dict:
    """Return {'nodes': [...], 'edges': [...], 'stats': {...}}."""
    events = list(events)
    skipped_no_source = 0
    skipped_self_loop = 0

    # Aggregate edges keyed by (source_host_key, target_host_key, user).
    edge_buckets: dict[tuple[str, str, str], dict] = {}
    node_buckets: dict[str, dict] = {}

    def touch_node(key: str, label: str, role: str):
        node = node_buckets.get(key)
        if node is None:
            node_buckets[key] = {
                "id": key,
                "label": label,
                "roles": {role},
                "count": 1,
            }
        else:
            node["roles"].add(role)
            node["count"] += 1
            # Upgrade label if we now know hostname+IP.
            if len(label) > len(node["label"]):
                node["label"] = label

    for ev in events:
        target_label = _host_label("", ev.get("computer", ""))
        target_key = _host_key("", ev.get("computer", ""))
        source_label = _host_label(ev.get("source_ip", ""), ev.get("source_host", ""))
        source_key = _host_key(ev.get("source_ip", ""), ev.get("source_host", ""))

        if source_key == target_key:
            skipped_self_loop += 1
            continue
        if source_key == "unknown":
            # Keep the event visible: route it from a sentinel node so the
            # user can still see that activity happened. Common for 4634/4647
            # logoff events that don't carry the client IP.
            skipped_no_source += 1
            source_key = "unknown-source"
            source_label = "(unknown source)"

        touch_node(target_key, target_label, "target")
        touch_node(source_key, source_label, "source")

        user = ev.get("user", "") or "?"
        # Windows accounts are case-insensitive, so "Administrator" and
        # "administrator" are the same user — key on the casefolded form
        # (display keeps the first-seen casing) to avoid duplicate edges.
        ekey = (source_key, target_key, user.casefold())
        bucket = edge_buckets.get(ekey)
        if bucket is None:
            bucket = {
                "from": source_key,
                "to": target_key,
                "user": user,
                "count": 0,
                "failed": 0,
                "success": 0,
                "first_seen": ev.get("timestamp", ""),
                "last_seen": ev.get("timestamp", ""),
                "event_ids": set(),
            }
            edge_buckets[ekey] = bucket

        bucket["count"] += 1
        bucket["event_ids"].add(ev.get("event_id"))
        ts = ev.get("timestamp", "")
        if ts and ts < bucket["first_seen"]:
            bucket["first_seen"] = ts
        if ts and ts > bucket["last_seen"]:
            bucket["last_seen"] = ts

        if ev.get("status") == "failed":
            bucket["failed"] += 1
        elif ev.get("status") == "success":
            bucket["success"] += 1

    # Render nodes for vis-network.
    nodes = []
    for key, n in node_buckets.items():
        roles = n["roles"]
        if "source" in roles and "target" in roles:
            color = "#f6c84c"   # both — pivot host
            group = "pivot"
        elif "target" in roles:
            color = "#5b8def"   # server
            group = "server"
        else:
            color = "#9aa5b1"   # client only
            group = "client"

        nodes.append({
            "id": key,
            "label": n["label"],
            "title": f"{n['label']}\nEvents: {n['count']}\nRole: {', '.join(sorted(roles))}",
            "value": n["count"],
            "color": color,
            "group": group,
        })

    edges = []
    for (src, dst, _user_key), b in edge_buckets.items():
        user = b["user"]   # original first-seen casing, not the casefolded key
        any_failed = b["failed"] > 0
        all_failed = b["failed"] > 0 and b["success"] == 0
        if all_failed:
            color = "#e74c3c"
        elif any_failed:
            color = "#e67e22"
        else:
            color = "#27ae60"

        edges.append({
            "from": src,
            "to": dst,
            "label": f"{user}  ×{b['count']}",
            "title": (
                f"User: {user}\n"
                f"Sessions: {b['count']}  "
                f"(success: {b['success']}, failed: {b['failed']})\n"
                f"Event IDs: {sorted(i for i in b['event_ids'] if i is not None)}\n"
                f"First: {b['first_seen']}\n"
                f"Last:  {b['last_seen']}"
            ),
            "value": b["count"],
            "color": {"color": color, "highlight": color},
            "arrows": "to",
            "user": user,
            "failed": b["failed"],
            "success": b["success"],
            "count": b["count"],
        })

    stats = {
        "events": len(events),
        "nodes": len(nodes),
        "edges": len(edges),
        "failed": sum(1 for e in events if e.get("status") == "failed"),
        "users": len({(e.get("user") or "").casefold() for e in events if e.get("user")}),
        "skipped_no_source": skipped_no_source,
        "skipped_self_loop": skipped_self_loop,
        "event_id_breakdown": _count_by_id(events),
    }

    return {"nodes": nodes, "edges": edges, "stats": stats}
