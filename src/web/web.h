#pragma once

#include <string>
#include <vector>
#include "httplib.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <filesystem>
#include "manager/Data.h"


struct ProxyServerInfo {
    int id;
    int client_port;
    int data_port;
    std::string comment;
    int last_seen; 
    int active_pairs;
    bool online;
};

class WebAdmin {
public:
    WebAdmin(std::shared_ptr<DataServers> ds,
        std::shared_ptr<ServerManager> sm,
        int port)
        : web_data_servers(std::move(ds)),
        web_server_manager(std::move(sm)),
        port_(port)
    {
    }
	~WebAdmin();

    
    void start();
    void stop();

private:
    bool m_running;
    std::shared_ptr<DataServers> web_data_servers;
    std::shared_ptr<ServerManager> web_server_manager;
    int port_;
    httplib::Server svr_;
};





// --- HTML CONTENT --- 

// This is a raw string literal containing the HTML, CSS, and JavaScript for the web admin interface.
// You can put this in a separate .html file and read it at runtime, but for simplicity, it's included directly in the code.

static const std::string INDEX_HTML = R"raw(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gray Proxy Admin</title>
    <style>
        :root {
            --bg-dark: #0f0f0f;
            --bg-panel: #1e1e1e;
            --accent: #2e7dff;
            --danger: #ff4444;
            --warning: #ffaa00;
            --text: #e0e0e0;
            --text-dim: #999;
            --terminal-bg: #0a0a0a;
        }

        body {
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            overflow-x: hidden;
        }

        header {
            padding: 15px 25px;
            background: #1b1b1b;
            font-size: 20px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #333;
        }

        .header-actions { display: flex; gap: 15px; align-items: center; }

        .btn-icon {
            cursor: pointer;
            width: 38px;
            height: 38px;
            background: #333;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: 0.2s;
            color: white;
            border: none;
            font-size: 18px;
        }

        .btn-icon:hover { background: #444; }
        .plus-btn { background: var(--accent); }

        .container { max-width: 900px; margin: 0 auto; padding: 20px; }

        .server {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            margin-bottom: 12px;
            border-radius: 8px;
            background: var(--bg-panel);
            border: 1px solid #2a2a2a;
        }

        .indicator { width: 10px; height: 10px; border-radius: 50%; margin-right: 15px; box-shadow: 0 0 8px currentColor; }
        .online { color: #00ff66; background: currentColor; }
        .offline { color: #555; background: currentColor; }

        .server-name { font-size: 18px; font-weight: bold; color: var(--accent); display: block; margin-bottom: 2px; }
        .small { font-size: 13px; color: var(--text-dim); margin-top: 4px; }
        .actions { display: flex; gap: 8px; }

        button { padding: 8px 14px; border: none; border-radius: 5px; cursor: pointer; font-weight: 500; transition: 0.2s; }
        .delete { background: #333; color: #ff7777; }
        .edit { background: #333; color: #ccc; }
        .stop { background: #333; color: var(--warning); }
        button:hover { filter: brightness(1.2); }

        /* Console Overlay */
        #consoleOverlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: var(--terminal-bg);
            z-index: 1000;
            display: none;
            flex-direction: column;
            padding: 20px;
        }

        .console-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 15px;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
        }

        #consoleContent {
            flex: 1;
            overflow-y: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-all;
            color: #fff;
            background: #000;
            padding: 10px;
        }

        /* --- LOG COLORS --- */
        .log-date { color: #666 !important; }
        .log-info { color: #00ff66 !important; font-weight: bold; }
        .log-error { color: #ff4444 !important; font-weight: bold; }
        .log-warn { color: #ffaa00 !important; font-weight: bold; }
        .log-debug { color: #2e7dff !important; font-weight: bold; }
        .log-msg { color: #ffffff !important; }

        /* Modal */
        .modal {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.85); display: none;
            justify-content: center; align-items: center; z-index: 100;
        }
        .modal-content { background: #1b1b1b; padding: 25px; border-radius: 10px; width: 320px; border: 1px solid #333; }
        input { width: 100%; padding: 10px; margin: 15px 0; background: #252525; border: 1px solid #444; color: white; border-radius: 4px; box-sizing: border-box; }
    </style>
</head>
<body>

<header>
    <span>Gray Proxy <span style="color:var(--accent)">Admin</span></span>
    <div class="header-actions">
        <button class="btn-icon" onclick="toggleConsole()" title="Console">📟</button>
        <button class="btn-icon plus-btn" onclick="openAddModal()" title="Add Server">+</button>
    </div>
</header>

<div class="container" id="servers"></div>

<div id="consoleOverlay">
    <div class="console-header">
        <span style="font-weight:bold; color:var(--accent)">System Log (obelisk.log)</span>
        <button onclick="toggleConsole()" style="background:var(--danger); color:white; padding: 8px 20px; border-radius: 5px; cursor: pointer;">Close</button>
    </div>
    <div id="consoleContent"></div>
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

        if (!res.ok) {
            console.error(`API Error: ${res.status} ${res.statusText}`);
            return { status: "error" };
        }

        try {
            const data = await res.json();
            return data;
        } catch (jsonError) {
            console.error("Invalid JSON from server:", jsonError);
            return { status: "error" };
        }

    } catch (networkError) {
        console.error("Network or fetch error:", networkError);
        return { status: "error" };
    }
}

async function loadServers() {
    const data = await api("/api/servers");
    if (!Array.isArray(data)) return;
    const container = document.getElementById("servers");
    container.innerHTML = "";
    data.forEach(server => {
        const div = document.createElement("div");
        div.className = "server";
        div.innerHTML = `
            <div style="display:flex; align-items:center">
                <div class="indicator ${server.online ? "online" : "offline"}"></div>
                <div class="server-info">
                    <span class="server-name" id="comm-${server.id}"></span>
                    <div class="small">ID: ${server.id} | Pairs: ${server.active_pairs} | Latency: ${server.last_seen} ms</div>
                    <div class="small">Ports: ${server.client_port} (Client) → ${server.data_port} (Data)</div>
                </div>
            </div>
            <div class="actions">
                ${server.online ? `<button class="stop" onclick="stopServer(${server.id})">Stop</button>` : ''}
                <button class="edit" onclick="openEditModal(${server.id}, '${server.comment}')">Edit</button>
                <button class="delete" onclick="deleteServer(${server.id})">Delete</button>
            </div>
        `;
        container.appendChild(div);
        document.getElementById(`comm-${server.id}`).textContent = server.comment || "No description";
    });
}

// Handler for Stop action
async function stopServer(id) {
    if (confirm(`Stop server ID: ${id}?`)) {
        const res = await api("/api/server/stop", { id });
        if (res.status === "ok") {
            loadServers();
        }
    }
}

async function updateConsole() {
    const data = await api("/api/logs");
    if (data && data.logs) {
        const el = document.getElementById("consoleContent");
        const shouldScroll = el.scrollTop + el.clientHeight >= el.scrollHeight - 50;
        
        const lines = data.logs.split('\n');
        const coloredHtml = lines.map(line => {
            if (!line.trim()) return "";
            let safeLine = line.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            let lvlClass = "log-msg";
            let levelLabel = "";

            if (safeLine.toLowerCase().includes("[info]")) {
                lvlClass = "log-info";
                levelLabel = "[INFO]";
            } else if (safeLine.toLowerCase().includes("[error]")) {
                lvlClass = "log-error";
                levelLabel = "[ERROR]";
            } else if (safeLine.toLowerCase().includes("[warn]")) {
                lvlClass = "log-warn";
                levelLabel = "[WARN]";
            } else if (safeLine.toLowerCase().includes("[debug]")) {
                lvlClass = "log-debug";
                levelLabel = "[DEBUG]";
            }

            const dateMatch = safeLine.match(/^\[(.*?)\]/);
            if (dateMatch) {
                const timestamp = dateMatch[1];
                let cleanText = safeLine.replace(/^\[.*?\]/, "").replace(/\[.*?\]/, "").trim();
                return `<span class="log-date">[${timestamp}]</span> ` +
                       `<span class="${lvlClass}">${levelLabel}</span> ` +
                       `<span class="log-msg">${cleanText}</span>`;
            }
            return `<span class="log-msg">${safeLine}</span>`;
        }).join('\n');

        el.innerHTML = coloredHtml;
        if (shouldScroll) el.scrollTop = el.scrollHeight;
    }
}

function toggleConsole() {
    const overlay = document.getElementById("consoleOverlay");
    consoleActive = !consoleActive;
    overlay.style.display = consoleActive ? "flex" : "none";
    if (consoleActive) {
        updateConsole();
        consoleInterval = setInterval(updateConsole, 2000);
    } else {
        clearInterval(consoleInterval);
    }
}

function openAddModal() {
    currentEditId = null;
    document.getElementById("modalTitle").innerText = "Add Server";
    document.getElementById("serverComment").value = "";
    document.getElementById("addModal").style.display = "flex";
}

function openEditModal(id, currentComment) {
    currentEditId = id;
    document.getElementById("modalTitle").innerText = "Edit Server";
    document.getElementById("serverComment").value = currentComment;
    document.getElementById("addModal").style.display = "flex";
}

function closeModal() { document.getElementById("addModal").style.display = "none"; }

async function submitModal() {
    const comment = document.getElementById("serverComment").value;
    if (currentEditId) await api("/api/server/change_comment", { id: currentEditId, comment });
    else await api("/api/server/add", { comment });
    closeModal();
    loadServers();
}

async function deleteServer(id) {
    if (confirm("Are you sure?")) {
        await api("/api/server/delete", { id });
        loadServers();
    }
}

setInterval(loadServers, 5000);
loadServers();
</script>
</body>
</html>
)raw";