"""Interactive Plotly network overview; ordinary scans do not reveal physical topology."""
from __future__ import annotations
import math
import plotly.graph_objects as go
from core.device_model import Device

COLORS = {"online": "#27c6a0", "offline": "#f26c6c", "unknown": "#f2b84b"}

def build_topology(devices: list[Device], *, mode: str = "simulation") -> go.Figure:
    fig = go.Figure()
    if not devices:
        fig.update_layout(title="No devices in this scan", template="plotly_dark", height=460)
        return fig
    ordered = sorted(devices, key=lambda d: (d.device_type != "Router", d.ip_address))
    router = next((d for d in ordered if d.device_type.lower() == "router"), None)
    center = router or ordered[0]
    # Links are only demonstrated/simulated or inferred visual relationships.
    edge_x, edge_y = [], []
    for i, device in enumerate(ordered):
        if device.device_id == center.device_id: continue
        angle = 2 * math.pi * (i - 1) / max(1, len(ordered) - 1)
        x, y = math.cos(angle), math.sin(angle)
        edge_x.extend([0, x, None]); edge_y.extend([0, y, None])
    if mode == "simulation":
        label = "Simulated connection"
    elif router:
        label = "Inferred relationship to observed router (not directly measured)"
    else:
        label = "Inferred visual link to map anchor; gateway unknown"
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines", line=dict(color="#60738b", width=1),
      hoverinfo="text", text=[label if v is not None else "" for v in edge_x], name=label))
    xs, ys, texts, colors, sizes = [], [], [], [], []
    for i, device in enumerate(ordered):
        if device.device_id == center.device_id: x, y = 0, 0
        else:
            angle = 2 * math.pi * (i - 1) / max(1, len(ordered) - 1)
            x, y = math.cos(angle), math.sin(angle)
        xs.append(x); ys.append(y); colors.append(COLORS.get(device.status.value, COLORS["unknown"]))
        sizes.append(25 if device.device_type.lower() == "router" else 17)
        texts.append(f"<b>{device.hostname or 'Unknown hostname'}</b><br>{device.ip_address}<br>{device.device_type}<br>Status: {device.status.value}<br>Source: {device.discovery_source}")
    node_labels = [d.hostname or d.ip_address for d in ordered]
    if mode != "simulation" and router is None:
        node_labels = [f"Anchor · {label}" if d.device_id == center.device_id else label for d, label in zip(ordered, node_labels)]
    fig.add_trace(go.Scatter(x=xs, y=ys, mode="markers+text", text=node_labels,
       textposition="bottom center", hovertext=texts, hoverinfo="text", marker=dict(size=sizes, color=colors, line=dict(color="#edf4fb", width=1)), name="Devices"))
    fig.update_layout(template="plotly_dark", height=520, title="Network map — observed devices; links are not a physical topology measurement",
      xaxis=dict(visible=False, range=[-1.45,1.45]), yaxis=dict(visible=False, range=[-1.45,1.45], scaleanchor="x", scaleratio=1),
      margin=dict(l=20,r=20,t=55,b=20), legend=dict(orientation="h", y=-0.1), dragmode="pan")
    return fig
