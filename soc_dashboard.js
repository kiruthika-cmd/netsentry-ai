/**
 * NetSentry AI - SOC Dashboard Analytics & Real-Time Monitoring Script
 * Powers Chart.js graphs, stats polling, and KPI updates.
 */

let trafficChart = null;
let protocolChart = null;

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    pollDashboardStats();
    setInterval(pollDashboardStats, 3000); // Poll every 3 seconds for live SOC updates
});

function initCharts() {
    // 1. Traffic Activity Line Chart
    const trafficCtx = document.getElementById("trafficActivityChart");
    if (trafficCtx) {
        trafficChart = new Chart(trafficCtx.getContext("2d"), {
            type: "line",
            data: {
                labels: ["--:--", "--:--", "--:--", "--:--", "--:--"],
                datasets: [{
                    label: "Packets / Minute",
                    data: [0, 0, 0, 0, 0],
                    borderColor: "#00d2ff",
                    backgroundColor: "rgba(0, 210, 255, 0.12)",
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 3,
                    pointBackgroundColor: "#00d2ff",
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { color: "rgba(34, 50, 84, 0.4)" },
                        ticks: { color: "#8da2c0", font: { size: 11 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(34, 50, 84, 0.4)" },
                        ticks: { color: "#8da2c0", font: { size: 11 }, precision: 0 }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // 2. Protocol Distribution Donut Chart
    const protocolCtx = document.getElementById("protocolDistributionChart");
    if (protocolCtx) {
        protocolChart = new Chart(protocolCtx.getContext("2d"), {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP", "HTTPS", "DNS", "Other"],
                datasets: [{
                    data: [1, 1, 1, 1, 1],
                    backgroundColor: [
                        "#0088ff",
                        "#00d2ff",
                        "#00cc88",
                        "#ffcc00",
                        "#ab9df2"
                    ],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#8da2c0", boxWidth: 12, font: { size: 11 } }
                    }
                },
                cutout: "70%"
            }
        });
    }
}

async function pollDashboardStats() {
    try {
        const res = await fetch("/api/stats");
        if (!res.ok) return;
        const data = await res.json();

        // Update KPI counters
        document.getElementById("totalPackets").innerText = Number(data.total_packets || 0).toLocaleString();
        document.getElementById("normalTraffic").innerText = Number(data.normal_traffic || 0).toLocaleString();
        document.getElementById("suspiciousTraffic").innerText = Number(data.suspicious_traffic || 0).toLocaleString();
        document.getElementById("criticalAlerts").innerText = data.alert_counts?.Critical || 0;

        // Update Protocol Donut Chart
        if (protocolChart && data.protocols && data.protocols.length > 0) {
            protocolChart.data.labels = data.protocols.map(p => p.protocol);
            protocolChart.data.datasets[0].data = data.protocols.map(p => p.count);
            protocolChart.update("none");
        }

        // Update Traffic Activity Trend
        if (trafficChart && data.traffic_trend && data.traffic_trend.length > 0) {
            trafficChart.data.labels = data.traffic_trend.map(t => t.time_slot);
            trafficChart.data.datasets[0].data = data.traffic_trend.map(t => t.count);
            trafficChart.update("none");
        }

        // Update Monitoring status badge
        const statusDot = document.getElementById("monitoringStatusDot");
        const statusText = document.getElementById("monitoringStatusText");
        if (statusDot && statusText) {
            if (data.monitoring_active) {
                statusDot.className = "status-dot active";
                statusText.innerText = data.simulated_mode ? "Simulated Lab Active" : "Live Capturing";
            } else {
                statusDot.className = "status-dot stopped";
                statusText.innerText = "Monitoring Idle";
            }
        }
    } catch (err) {
        console.warn("Failed to update dashboard stats:", err);
    }
}

