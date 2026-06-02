"""Parse Windows .evtx files and extract RDP-related session events.

Yields normalized records of the form:
    {
        "timestamp": iso8601 str,
        "event_id": int,
        "channel": str,
        "computer": str,          # the host that produced the log (target of RDP)
        "user": str,              # account name (may be empty for some 1149)
        "domain": str,
        "source_ip": str,         # the RDP client's address
        "source_host": str,       # client workstation name when known
        "logon_type": int | None,
        "session_id": str,
        "status": "success" | "failed" | "logoff" | "disconnect" | "reconnect",
        "raw_xml": str,
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Iterator, Optional

from Evtx.Evtx import Evtx
from lxml import etree


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Event IDs we care about, by channel.
SECURITY_IDS = {4624, 4625, 4634, 4647, 4778, 4779}
LSM_IDS = {21, 22, 23, 24, 25}  # TerminalServices-LocalSessionManager/Operational
RCM_IDS = {1149}                 # TerminalServices-RemoteConnectionManager/Operational

# Status mapping per event id.
STATUS_BY_ID = {
    4624: "success",
    4625: "failed",
    4634: "logoff",
    4647: "logoff",
    4778: "reconnect",
    4779: "disconnect",
    21: "success",
    22: "success",     # shell start — treat as session activity
    23: "logoff",
    24: "disconnect",
    25: "reconnect",
    1149: "success",
}


@dataclass
class RDPEvent:
    timestamp: str
    event_id: int
    channel: str
    computer: str
    user: str
    domain: str
    source_ip: str
    source_host: str
    logon_type: Optional[int]
    session_id: str
    status: str
    raw_xml: str

    def to_dict(self) -> dict:
        return asdict(self)


def _text(el, xpath: str) -> str:
    """Find a sub-element via xpath and return its text or empty string."""
    found = el.find(xpath, NS)
    if found is None or found.text is None:
        return ""
    return found.text.strip()


def _data(event_data_el, name: str) -> str:
    """Extract a <Data Name='X'>value</Data> from EventData."""
    if event_data_el is None:
        return ""
    node = event_data_el.find(f"e:Data[@Name='{name}']", NS)
    if node is None or node.text is None:
        return ""
    return node.text.strip()


def _is_rdp_logon_type(lt: str) -> bool:
    """LogonType 10 = RemoteInteractive, 7 = Unlock (often via RDP reconnect).

    Some defenders also include 3 when LogonProcessName == 'RDP' but that's
    noisy; we stick to 10 for 4624/4625.
    """
    return lt == "10"


_CLIENT_NAME_RE = re.compile(r"Source Network Address:\s*(\S+)", re.IGNORECASE)


def _normalize_event(xml_bytes: bytes) -> Optional[RDPEvent]:
    """Parse a single <Event>...</Event> blob; return RDPEvent or None to skip."""
    try:
        # python-evtx already returns a string; wrap defensively.
        if isinstance(xml_bytes, bytes):
            root = etree.fromstring(xml_bytes)
        else:
            root = etree.fromstring(xml_bytes.encode("utf-8"))
    except etree.XMLSyntaxError:
        return None

    system = root.find("e:System", NS)
    if system is None:
        return None

    event_id_text = _text(system, "e:EventID")
    if not event_id_text:
        return None
    try:
        event_id = int(event_id_text)
    except ValueError:
        return None

    channel = _text(system, "e:Channel")
    timestamp = ""
    time_node = system.find("e:TimeCreated", NS)
    if time_node is not None:
        timestamp = time_node.get("SystemTime", "")
    computer = _text(system, "e:Computer")

    event_data = root.find("e:EventData", NS)
    user_data = root.find("e:UserData", NS)

    # --- Security channel ---
    if event_id in SECURITY_IDS and "Security" in channel:
        logon_type_str = _data(event_data, "LogonType")
        if event_id in (4624, 4625) and not _is_rdp_logon_type(logon_type_str):
            return None  # not RDP

        target_user = _data(event_data, "TargetUserName")
        target_domain = _data(event_data, "TargetDomainName")
        ip = _data(event_data, "IpAddress")
        if ip in ("-", "::1", "127.0.0.1"):
            ip = ""
        workstation = _data(event_data, "WorkstationName")
        session_id = _data(event_data, "TargetLogonId")

        # 4778/4779 use different field names
        if event_id in (4778, 4779):
            target_user = _data(event_data, "AccountName") or target_user
            target_domain = _data(event_data, "AccountDomain") or target_domain
            ip = _data(event_data, "ClientAddress") or ip
            workstation = _data(event_data, "ClientName") or workstation
            session_id = _data(event_data, "LogonID") or session_id

        return RDPEvent(
            timestamp=timestamp,
            event_id=event_id,
            channel=channel,
            computer=computer,
            user=target_user,
            domain=target_domain,
            source_ip=ip,
            source_host=workstation,
            logon_type=int(logon_type_str) if logon_type_str.isdigit() else None,
            session_id=session_id,
            status=STATUS_BY_ID.get(event_id, "success"),
            raw_xml=etree.tostring(root, pretty_print=True).decode("utf-8", "replace"),
        )

    # --- TerminalServices-LocalSessionManager ---
    if event_id in LSM_IDS and "LocalSessionManager" in channel:
        # LSM events use <UserData><EventXML> with custom fields (no namespace
        # inside that block in many builds).
        user = ""
        session_id = ""
        ip = ""
        if user_data is not None:
            # Strip namespaces from children for resilient lookup.
            for child in user_data.iter():
                tag = etree.QName(child).localname
                if tag == "User" and child.text:
                    user = child.text.strip()
                elif tag == "SessionID" and child.text:
                    session_id = child.text.strip()
                elif tag == "Address" and child.text:
                    ip = child.text.strip()

        domain = ""
        if "\\" in user:
            domain, user = user.split("\\", 1)

        if ip in ("LOCAL", "-"):
            ip = ""

        return RDPEvent(
            timestamp=timestamp,
            event_id=event_id,
            channel=channel,
            computer=computer,
            user=user,
            domain=domain,
            source_ip=ip,
            source_host="",
            logon_type=None,
            session_id=session_id,
            status=STATUS_BY_ID.get(event_id, "success"),
            raw_xml=etree.tostring(root, pretty_print=True).decode("utf-8", "replace"),
        )

    # --- TerminalServices-RemoteConnectionManager 1149 ---
    if event_id in RCM_IDS and "RemoteConnectionManager" in channel:
        user = ""
        domain = ""
        ip = ""
        if user_data is not None:
            for child in user_data.iter():
                tag = etree.QName(child).localname
                if tag == "Param1" and child.text:
                    user = child.text.strip()
                elif tag == "Param2" and child.text:
                    domain = child.text.strip()
                elif tag == "Param3" and child.text:
                    ip = child.text.strip()

        return RDPEvent(
            timestamp=timestamp,
            event_id=event_id,
            channel=channel,
            computer=computer,
            user=user,
            domain=domain,
            source_ip=ip,
            source_host="",
            logon_type=None,
            session_id="",
            status="success",
            raw_xml=etree.tostring(root, pretty_print=True).decode("utf-8", "replace"),
        )

    return None


def parse_evtx(path: str) -> Iterator[RDPEvent]:
    """Yield RDPEvent records from an .evtx file. Silently skips unrelated events."""
    with Evtx(path) as log:
        for record in log.records():
            try:
                xml = record.xml()
            except Exception:
                continue
            evt = _normalize_event(xml)
            if evt is not None:
                yield evt


def parse_many(paths: list[str]) -> list[dict]:
    """Parse several files and return a flat list of dicts, sorted by timestamp."""
    events: list[dict] = []
    for p in paths:
        for evt in parse_evtx(p):
            events.append(evt.to_dict())
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events
