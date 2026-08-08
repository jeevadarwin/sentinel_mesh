"""
main.py — Standalone Sandbox Firewall Service for Sentinel Mesh.

Maintains an in-memory active block-list representing an isolated network firewall appliance.
Provides HTTP API endpoints for adding blocks, querying block status, and retrieving full block-lists.
"""

from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="Sentinel Mesh — Sandbox Firewall Service",
    description="Isolated network firewall simulator for testing automated containment actions.",
    version="1.0.0",
)

# In-memory storage for blocked IPs
_BLOCKLIST: Dict[str, Dict[str, Any]] = {}


class BlockRequest(BaseModel):
    ip: str = Field(..., description="IPv4 or IPv6 address to block.")
    reason: str = Field(default="Sentinel Mesh automated containment", description="Reason for block rule.")


@app.post("/block")
async def block_ip(request: BlockRequest):
    """Add an IP address to the firewall block-list."""
    ip = request.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP address cannot be empty.")
    
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "ip": ip,
        "blocked": True,
        "reason": request.reason,
        "blocked_at": timestamp,
    }
    _BLOCKLIST[ip] = record
    return {
        "status": "blocked",
        "ip": ip,
        "blocked_at": timestamp,
        "message": f"Firewall rule added: DROP all traffic to/from {ip}",
    }


@app.get("/blocked/{ip}")
async def check_blocked(ip: str):
    """Check whether a specific IP address is currently blocked in the firewall."""
    ip_clean = ip.strip()
    record = _BLOCKLIST.get(ip_clean)
    if record:
        return {
            "ip": ip_clean,
            "blocked": True,
            "blocked_at": record["blocked_at"],
            "reason": record["reason"],
        }
    return {
        "ip": ip_clean,
        "blocked": False,
        "blocked_at": None,
        "reason": "Not present in block-list",
    }


@app.get("/blocklist")
async def get_blocklist():
    """Retrieve the full list of currently blocked IP addresses."""
    return {
        "count": len(_BLOCKLIST),
        "blocked_ips": list(_BLOCKLIST.values()),
    }


@app.delete("/unblock/{ip}")
async def unblock_ip(ip: str):
    """Remove an IP address from the firewall block-list."""
    ip_clean = ip.strip()
    if ip_clean in _BLOCKLIST:
        del _BLOCKLIST[ip_clean]
        return {"status": "unblocked", "ip": ip_clean}
    raise HTTPException(status_code=404, detail=f"IP {ip_clean} not found in block-list.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8002)
