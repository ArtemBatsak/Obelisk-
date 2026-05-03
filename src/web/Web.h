﻿#pragma once
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <string>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <iostream>
#include <fstream>
#include "manager/Data.h"
#include "manager/Server_manager.h"
#include "tls/Tls_session.h"
#include "manager/Setup_wizard.h"


struct ProxyServerInfo {
    int id;
    int client_port;
    std::string comment;
    int last_seen;
    int active_pairs;
    bool online;
};

class WebAdmin {
public:
    WebAdmin(std::shared_ptr<DataServers> ds,
        std::shared_ptr<ServerManager> sm,
        std::shared_ptr<ConfigManager> wi,
        int port)
        : web_data_servers(std::move(ds)),
        web_server_manager(std::move(sm)),
        web_wizard(std::move(wi)),
        port_(port),
        m_running(false)
    {
    }

    ~WebAdmin();

    void start();
    void stop();

private:

    bool m_running;
    int port_;
    std::shared_ptr<DataServers> web_data_servers;
    std::shared_ptr<ServerManager> web_server_manager;
    std::shared_ptr<ConfigManager> web_wizard;
    std::string tls_cert_path;
    std::string tls_key_path;
    std::unique_ptr<httplib::SSLServer> svr;

    void apply_auth_middleware();
    void setup_tls_in_memory();
    std::string detect_external_ip() const;
};





// --- HTML CONTENT --- 

// This is a raw string literal containing the HTML, CSS, and JavaScript for the web admin interface.
// You can put this in a separate .html file and read it at runtime, but for simplicity, it's included directly in the code.


static const std::string INDEX_HTML_PART_1 = R"raw(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gray Proxy Admin</title>
    <style>
        :root {
            --bg-dark: #0f0f0f; --bg-panel: #1e1e1e; --accent: #2e7dff;
            --danger: #ff4444; --warning: #ffaa00; --success: #00ff66;
            --text: #e0e0e0; --text-dim: #999; --terminal-bg: #0a0a0a;
        }
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background: var(--bg-dark); color: var(--text); overflow-x: hidden; }
        header { padding: 15px 25px; background: #1b1b1b; font-size: 20px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; }
        .header-actions { display: flex; gap: 15px; align-items: center; }
        .btn-icon { cursor: pointer; width: 38px; height: 38px; background: #333; border-radius: 8px; display: flex; align-items: center; justify-content: center; transition: 0.2s; color: white; border: none; font-size: 18px; }
        .btn-icon:hover { background: #444; }
        .manage-btn { background: var(--accent); }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        .server { display: flex; justify-content: space-between; align-items: center; padding: 15px; margin-bottom: 12px; border-radius: 8px; background: var(--bg-panel); border: 1px solid #2a2a2a; }
        .indicator { width: 10px; height: 10px; border-radius: 50%; margin-right: 15px; box-shadow: 0 0 8px currentColor; }
        .online { color: var(--success); background: currentColor; }
        .offline { color: #555; background: currentColor; }
        .server-name { font-size: 18px; font-weight: bold; color: var(--accent); display: block; margin-bottom: 2px; }
        .small { font-size: 13px; color: var(--text-dim); margin-top: 4px; }
        .actions { display: flex; gap: 8px; }
        button { padding: 8px 14px; border: none; border-radius: 5px; cursor: pointer; font-weight: 500; transition: 0.2s; }
        .delete { background: #333; color: #ff7777; }
        .edit { background: #333; color: #ccc; }
        .stop { background: #333; color: var(--warning); }
        .primary-btn { background: var(--accent); color: white; width: 100%; margin-bottom: 10px; font-size: 15px; padding: 12px; }
        button:hover { filter: brightness(1.2); }
        #consoleOverlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: var(--terminal-bg); z-index: 1000; display: none; flex-direction: column; padding: 20px; }
        .console-header { display: flex; justify-content: space-between; margin-bottom: 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }
        #consoleContent { flex: 1; overflow-y: auto; font-family: monospace; font-size: 14px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; color: #fff; background: #000; padding: 10px; }
        .modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); display: none; justify-content: center; align-items: center; z-index: 100; }
        .modal-content { background: #1b1b1b; padding: 25px; border-radius: 10px; width: 320px; border: 1px solid #333; }
        input { width: 100%; padding: 10px; margin: 15px 0; background: #252525; border: 1px solid #444; color: white; border-radius: 4px; box-sizing: border-box; }
        .port-range-inputs { display: flex; align-items: center; gap: 10px; }
        .port-pool-view { background: #000; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 13px; max-height: 150px; overflow-y: auto; margin: 10px 0; border: 1px solid #333; color: var(--success); }
    </style>
</head>
<body>
<header>
    <span>Gray Proxy <span style="color:var(--accent)">Admin</span></span>
    <div class="header-actions">
        <button class="btn-icon" onclick="toggleConsole()" title="System Console">📟</button>
        <button class="btn-icon manage-btn" onclick="openManageModal()" title="Manage System">⚙️</button>
    </div>
</header>
<div class="container" id="servers"></div>
<div class="modal" id="manageModal">
    <div class="modal-content">
        <h3 style="margin-top:0">Management</h3>
        <button class="primary-btn" onclick="triggerAddClient()">👤 Add Client</button>
        <button class="primary-btn" onclick="triggerManagePorts()">🔌 Add Ports</button>
        <button class="primary-btn" style="background: #444;" onclick="triggerViewPorts()">📋 View Free Ports</button>
        <button class="primary-btn" style="background: #500;" onclick="triggerDeletePorts()">❌ Delete Ports</button>
        <button class="delete" style="width:100%; margin-top: 10px;" onclick="closeManageModal()">Close</button>
    </div>
</div>
<div class="modal" id="viewPortsModal">
    <div class="modal-content" style="width: 400px;">
        <h3 style="margin-top:0">Free Ports Pool</h3>
        <div id="portsListContent" class="port-pool-view">Loading...</div>
        <button class="primary-btn" onclick="closeViewPortsModal()">Close</button>
    </div>
</div>
<div id="consoleOverlay">
    <div class="console-header">
        <span style="font-weight:bold; color:var(--accent)">System Log</span>
        <button onclick="toggleConsole()" style="background:var(--danger); color:white; padding: 8px 20px; border-radius: 5px; cursor: pointer;">Close</button>
    </div>
    <div id="consoleContent"></div>
</div>
<div class="modal" id="portsModal">
    <div class="modal-content">
        <h3 id="portsModalTitle" style="margin-top:0">Add Free Ports</h3>
        <p class="small" style="color: var(--text-dim); margin-bottom: 5px;">Enter a single port or a range.</p>
        <div class="port-range-inputs">
            <input id="portFirst" type="number" placeholder="From" min="1025" max="65535">
            <span>-</span>
            <input id="portSecond" type="number" placeholder="To" min="1025" max="65535">
        </div>
        <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button id="portSubmitBtn" class="edit" style="flex: 1; background:var(--accent); color:white">Submit</button>
            <button class="delete" style="flex: 1" onclick="closePortsModal()">Cancel</button>
        </div>
    </div>
</div>
<div class="modal" id="addModal">
    <div class="modal-content">
        <h3 id="modalTitle" style="margin-top:0">Add Server</h3>
        <input id="serverComment" placeholder="Enter description...">
        <div style="display: flex; gap: 10px;">
            <button class="edit" style="flex: 1; background:var(--accent); color:white" onclick="submitModal()">Save</button>
            <button class="delete" style="flex: 1" onclick="closeModal()">Cancel</button>
        </div>
    </div>
</div>
)raw";

static const std::string INDEX_JS_PART_2 = R"raw(
<script>
let currentEditId = null;
let consoleActive = false;
let consoleInterval = null;

async function api(path, body = null) {
    try {
        const options = {
            method: body ? "POST" : "GET",
            headers: {"Content-Type": "application/json"}
        };
        if (body) options.body = JSON.stringify(body);
        const res = await fetch(path, options);
        if (!res.ok) return { status: "error" };
        return await res.json();
    } catch (e) { return { status: "error" }; }
}

function updateText(id, value) {
    const el = document.getElementById(id);
    if (el && el.textContent !== String(value)) el.textContent = value;
}

async function loadServers() {
    const data = await api("/api/servers");
    if (!Array.isArray(data)) return;
    const container = document.getElementById("servers");
    const activeIds = new Set();

    data.forEach(server => {
        const cardId = `server-card-${server.id}`;
        activeIds.add(cardId);
        let card = document.getElementById(cardId);
        if (!card) {
            card = document.createElement("div");
            card.id = cardId;
            card.className = "server";
            card.innerHTML = `
                <div style="display:flex; align-items:center">
                    <div id="ind-${server.id}" class="indicator"></div>
                    <div class="server-info">
                        <span class="server-name" id="comm-${server.id}"></span>
                        <div class="small">ID: ${server.id} | Pairs: <span id="pairs-${server.id}" style="color:var(--accent)">0</span> | Latency: <span id="lat-${server.id}">0</span> ms</div>
                        <div class="small">Speed In: <span id="speed-in-${server.id}">0</span> | Speed Out: <span id="speed-out-${server.id}">0</span></div>
                        <div class="small">Total Traffic: <span id="traffic-${server.id}">0</span></div>
                        <div class="small">Port: ${server.client_port} (Client)</div>
                    </div>
                </div>
                <div class="actions" id="actions-${server.id}"></div>`;
            container.appendChild(card);
        }
        updateText(`comm-${server.id}`, server.comment || "No description");
        updateText(`pairs-${server.id}`, server.active_pairs);
        updateText(`lat-${server.id}`, server.last_seen);
        updateText(`speed-in-${server.id}`, formatBytes(server.speed_in || 0) + "/s");
        updateText(`speed-out-${server.id}`, formatBytes(server.speed_out || 0) + "/s");
        updateText(`traffic-${server.id}`, formatBytes(server.total_traffic || 0));

        const ind = document.getElementById(`ind-${server.id}`);
        const statusClass = server.online ? "online" : "offline";
        if (!ind.classList.contains(statusClass)) ind.className = `indicator ${statusClass}`;

        const act = document.getElementById(`actions-${server.id}`);
        const stateKey = server.online ? "on" : "off";
        if (act.dataset.state !== stateKey) {
            act.dataset.state = stateKey;
            act.innerHTML = `
                ${server.online ? `<button class="stop" onclick="stopServer(${server.id})">Stop</button>` : ''}
                <button class="edit" onclick="downloadConfig(${server.id})">Config</button>
                <button class="edit" onclick="openEditModal(${server.id}, '${server.comment}')">Edit</button>
                <button class="delete" onclick="deleteServer(${server.id})">Delete</button>`;
        }
    });
    Array.from(container.children).forEach(child => { if (!activeIds.has(child.id)) child.remove(); });
}

function openManageModal() { document.getElementById("manageModal").style.display = "flex"; }
function closeManageModal() { document.getElementById("manageModal").style.display = "none"; }
function triggerAddClient() { closeManageModal(); openAddModal(); }
function openAddModal() { currentEditId = null; document.getElementById("modalTitle").innerText = "Add Server"; document.getElementById("serverComment").value = ""; document.getElementById("addModal").style.display = "flex"; }
function openEditModal(id, currentComment) { currentEditId = id; document.getElementById("modalTitle").innerText = "Edit Server"; document.getElementById("serverComment").value = currentComment; document.getElementById("addModal").style.display = "flex"; }
function closeModal() { document.getElementById("addModal").style.display = "none"; }

async function submitModal() {
    const comment = document.getElementById("serverComment").value;
    const res = currentEditId ? await api("/api/server/change_comment", { id: currentEditId, comment }) : await api("/api/server/add", { comment });
    if (res.status === "ok" || res.status === "success") { closeModal(); loadServers(); } else { alert("Action failed"); }
}

function triggerManagePorts() { closeManageModal(); const modal = document.getElementById("portsModal"); document.getElementById("portsModalTitle").innerText = "Add Free Ports"; const btn = document.getElementById("portSubmitBtn"); btn.innerText = "Add Range"; btn.style.background = "var(--accent)"; btn.onclick = submitPorts; modal.style.display = "flex"; }
function triggerDeletePorts() { closeManageModal(); const modal = document.getElementById("portsModal"); document.getElementById("portsModalTitle").innerText = "Delete Ports"; const btn = document.getElementById("portSubmitBtn"); btn.innerText = "Delete Range"; btn.style.background = "var(--danger)"; btn.onclick = submitDeletePorts; modal.style.display = "flex"; }
function closePortsModal() { document.getElementById("portsModal").style.display = "none"; document.getElementById("portFirst").value = ""; document.getElementById("portSecond").value = ""; }

async function submitPorts() {
    const f = document.getElementById("portFirst").value;
    const s = document.getElementById("portSecond").value;
    if (!f) return alert("Enter port!");
    const res = await api("/api/ports/add", { first: parseInt(f), second: s ? parseInt(s) : 0 });
    if (res.status === "ok") { closePortsModal(); alert("Ports added!"); }
}

async function submitDeletePorts() {
    const f = document.getElementById("portFirst").value;
    const s = document.getElementById("portSecond").value;
    if (!f) return alert("Enter port!");
    if(!confirm("Are you sure?")) return;
    const res = await api("/api/ports/delete", { first: parseInt(f), second: s ? parseInt(s) : 0 });
    if (res.status === "ok") { closePortsModal(); alert("Ports deleted!"); }
}

async function triggerViewPorts() {
    closeManageModal(); document.getElementById("viewPortsModal").style.display = "flex";
    const data = await api("/api/ports/list");
    const content = document.getElementById("portsListContent");
    content.innerHTML = `<div>Total: ${data.count || 0}</div><div>${data.ranges || 'Empty'}</div>`;
}
function closeViewPortsModal() { document.getElementById("viewPortsModal").style.display = "none"; }

async function stopServer(id) { if (confirm(`Stop server ${id}?`)) { await api("/api/server/stop", { id }); loadServers(); } }
async function deleteServer(id) { if (confirm("Are you sure?")) { await api("/api/server/delete", { id }); loadServers(); } }
function downloadConfig(id) { window.location.href = `/api/server/config?id=${id}`; }

async function updateConsole() {
    const data = await api("/api/logs");
    if (data && data.logs) {
        const el = document.getElementById("consoleContent");
        if (el.dataset.lastLog !== data.logs) {
            const shouldScroll = el.scrollTop + el.clientHeight >= el.scrollHeight - 50;
            el.textContent = data.logs;
            el.dataset.lastLog = data.logs;
            if (shouldScroll) el.scrollTop = el.scrollHeight;
        }
    }
}

function toggleConsole() {
    const overlay = document.getElementById("consoleOverlay");
    consoleActive = !consoleActive;
    overlay.style.display = consoleActive ? "flex" : "none";
    if (consoleActive) { updateConsole(); consoleInterval = setInterval(updateConsole, 2000); } else { clearInterval(consoleInterval); }
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}

setInterval(loadServers, 1000);
loadServers();
</script>
</body>
</html>
)raw";