/**
 * NetSentry AI - Live Packet Stream & Real-Time Controller
 */

let isStreamRunning = false;
let streamPollInterval = null;
let lastPacketId = 0;

document.addEventListener("DOMContentLoaded", () => {
    checkMonitoringState();
    
    const startBtn = document.getElementById("btnStartMonitoring");
    const stopBtn = document.getElementById("btnStopMonitoring");
    const clearBtn = document.getElementById("btnClearStream");

    if (startBtn) startBtn.addEventListener("click", startMonitoring);
    if (stopBtn) stopBtn.addEventListener("click", stopMonitoring);
    if (clearBtn) clearBtn.addEventListener("click", clearStreamTable);
});

async function checkMonitoringState() {
    try {
        const res = await fetch("/api/monitoring/status");
        const data = await res.json();
        updateUIState(data.is_running, data.simulated_mode);
        if (data.is_running) {
            startPollingStream();
        }
    } catch (e) {
        console.error("Failed to check monitoring status:", e);
    }
}

async function startMonitoring() {
    try {
        const iface = document.getElementById("interfaceSelect")?.value || "default";
        const res = await fetch("/api/monitoring/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: iface })
        });
        const data = await res.json();
        if (data.status === "success") {
            updateUIState(true, data.simulated_mode);
            startPollingStream();
        }
    } catch (e) {
        alert("Failed to start monitoring: " + e.message);
    }
}

async function stopMonitoring() {
    try {
        const res = await fetch("/api/monitoring/stop", { method: "POST" });
        const data = await res.json();
        updateUIState(false);
        stopPollingStream();
    } catch (e) {
        alert("Failed to stop monitoring: " + e.message);
    }
}

function updateUIState(running, simulated = false) {
    isStreamRunning = running;
    const startBtn = document.getElementById("btnStartMonitoring");
    const stopBtn = document.getElementById("btnStopMonitoring");
    const badge = document.getElementById("streamStateBadge");

    if (startBtn && stopBtn) {
        startBtn.disabled = running;
        stopBtn.disabled = !running;
    }

    if (badge) {
        if (running) {
            badge.className = "badge badge-low";
            badge.innerText = simulated ? "RUNNING (SIMULATED LAB)" : "CAPTURING LIVE";
        } else {
            badge.className = "badge";
            badge.style.backgroundColor = "var(--border-color)";
            badge.style.color = "var(--text-muted)";
            badge.innerText = "STOPPED";
        }
    }
}

function startPollingStream() {
    if (streamPollInterval) clearInterval(streamPollInterval);
    streamPollInterval = setInterval(fetchRecentPackets, 1500);
}

function stopPollingStream() {
    if (streamPollInterval) {
        clearInterval(streamPollInterval);
        streamPollInterval = null;
    }
}

async function fetchRecentPackets() {
    try {
        const res = await fetch("/api/monitoring/packets?limit=25");
        const packets = await res.json();
        renderPacketRows(packets);
    } catch (e) {
        console.warn("Error fetching packet stream:", e);
    }
}

function renderPacketRows(packets) {
    const tbody = document.getElementById("packetStreamBody");
    if (!tbody || !packets || packets.length === 0) return;

    // Filter to only new packets
    const newPackets = packets.filter(p => p.id > lastPacketId);
    if (newPackets.length === 0) return;

    lastPacketId = Math.max(...packets.map(p => p.id));

    // Prepend new packets
    newPackets.reverse().forEach(p => {
        const row = document.createElement("tr");
        if (p.is_suspicious) {
            row.style.backgroundColor = "rgba(255, 51, 102, 0.08)";
        }

        const sevBadge = p.is_suspicious 
            ? `<span class="badge badge-critical">SUSPICIOUS</span>` 
            : `<span class="badge badge-low">NORMAL</span>`;

        row.innerHTML = `
            <td>${p.timestamp}</td>
            <td><strong>${p.src_ip}</strong>${p.src_port ? ':' + p.src_port : ''}</td>
            <td><strong>${p.dst_ip}</strong>${p.dst_port ? ':' + p.dst_port : ''}</td>
            <td><span class="badge badge-proto">${p.protocol}</span></td>
            <td>${p.length} B</td>
            <td>${sevBadge}</td>
            <td style="color: ${p.anomaly_score < -0.1 ? '#ff3366' : '#8da2c0'}; font-weight: 600;">
                ${p.anomaly_score.toFixed(3)}
            </td>
            <td style="color: var(--text-muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${p.info || ''}
            </td>
        `;

        tbody.insertBefore(row, tbody.firstChild);
    });

    // Limit visible rows in DOM to avoid performance lag
    while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }
}

function clearStreamTable() {
    const tbody = document.getElementById("packetStreamBody");
    if (tbody) tbody.innerHTML = "";
    lastPacketId = 0;
}

