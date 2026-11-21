(function () {
  const log = document.getElementById("outputLog");
  const anchorAddrEl = document.getElementById("anchorAddress");
  const anchorPubEl = document.getElementById("anchorPubkey");
  const burnedEl = document.getElementById("burnedDisplay");
  const approvedEl = document.getElementById("approvedCount");
  const deniedEl = document.getElementById("deniedCount");
  const teamCallEl = document.getElementById("teamCallDisplay");
  const keyModeSel = document.getElementById("keyModeSelect");
  const fidoNameEl = document.getElementById("fidoName");
  const fidoAaguidEl = document.getElementById("fidoAaguid");
  const fidoLevelEl = document.getElementById("fidoLevel");
  const fidoStatusBadge = document.getElementById("fidoStatusBadge");
  const fidoWarningEl = document.getElementById("fidoWarning");

  const offersTable = document.getElementById("offersTable");
  const offersTbody = document.getElementById("offersTbody");
  const noOffersMsg = document.getElementById("noOffersMsg");
  const offersCountBadge = document.getElementById("offersCountBadge");

  const agentsTable = document.getElementById("agentsTable");
  const agentsTbody = document.getElementById("agentsTbody");
  const noAgentsMsg = document.getElementById("noAgentsMsg");
  const agentsCountBadge = document.getElementById("agentsCountBadge");

  const meshStatusBadge = document.getElementById("meshStatusBadge");
  const connectMeshBtn = document.getElementById("connectMeshBtn");
  const targetPeerInput = document.getElementById("targetPeerInput");
  const openChannelBtn = document.getElementById("openChannelBtn");
  const sessionsCountBadge = document.getElementById("sessionsCountBadge");
  const noSessionsMsg = document.getElementById("noSessionsMsg");
  const sessionsList = document.getElementById("sessionsList");
  const activePeerLabel = document.getElementById("activePeerLabel");
  const chatMessages = document.getElementById("chatMessages");
  const chatInput = document.getElementById("chatInput");
  const sendMessageBtn = document.getElementById("sendMessageBtn");

  function sanitizeLogData(obj) {
    if (!obj || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(sanitizeLogData);
    const forbidden = new Set([
      "seed", "seed-bytes", "seed_bytes", "seedBytes",
      "private-key", "private_key", "privateKey", "privkey",
      "privkey-bytes", "privkey_bytes", "privkeyBytes",
      "privkey-hex", "privkey_hex", "privkeyHex",
      "cold-privkey", "cold_privkey", "coldPrivkey",
      "keypair", "id", "rawId", "raw_id", "raw-id",
      "userHandle", "user_handle", "user-handle",
      "x25519", "ephemeral-priv", "ephemeral_priv", "ephemeralPriv",
      "tx-key", "tx_key", "txKey", "rx-key", "rx_key", "rxKey",
      "session-keys", "session_keys", "sessionKeys",
      "shared-secret", "shared_secret", "sharedSecret",
      "prfOutput", "prf_output", "prf-output",
      "backup-seed", "backup_seed", "backupSeed"
    ]);
    const clean = {};
    for (const k of Object.keys(obj)) {
      if (!forbidden.has(k)) {
        clean[k] = sanitizeLogData(obj[k]);
      }
    }
    return clean;
  }

  function writeLog(title, data) {
    const time = new Date().toISOString().substring(11, 19);
    const cleanData = data ? sanitizeLogData(data) : null;
    const text = "[" + time + "] " + title + (cleanData ? "\n" + JSON.stringify(cleanData, null, 2) : "");
    log.textContent = text + "\n\n" + log.textContent.slice(0, 5000);
  }

  function updateUI(dash) {
    if (!dash) return;
    const ident = dash.identity || {};
    const acct = dash.accounting || {};

    anchorAddrEl.textContent = ident.address || dash["anchor-address"] || dash.anchorAddress || "Not initialized";
    anchorPubEl.textContent = (ident["anchor-pubkey"] || dash["anchor-pubkey"] || dash.anchorPubkey || "").slice(0, 32) + "...";
    const hwLockedBadge = document.getElementById("hardwareLockedBadge");
    const isHwLocked = Boolean(ident["hardware-locked"] || ident.hardwareLocked || dash["hardware-locked"] || dash.hardwareLocked);
    if (hwLockedBadge) {
      hwLockedBadge.style.display = isHwLocked ? "inline-block" : "none";
    }
    burnedEl.textContent = (acct["burned-ech"] ?? dash["total-burned"] ?? dash.totalBurned ?? 0) + " ECH";
    approvedEl.textContent = acct["offers-approved"] ?? dash["offers-approved"] ?? dash.offersApproved ?? 0;
    deniedEl.textContent = acct["offers-denied"] ?? dash["offers-denied"] ?? dash.offersDenied ?? 0;

    const balanceEl = document.getElementById("balanceDisplay");
    if (balanceEl) {
      const bal = acct.balance ?? dash.balance ?? 0;
      balanceEl.textContent = Number(bal).toLocaleString() + " ECH";
    }

    const tc = dash["team-call-subnet"] || dash.teamCallSubnet;
    if (tc && (tc["subnet-id"] || tc.subnetId)) {
      const sid = tc["subnet-id"] || tc.subnetId;
      const topic = tc["topic-name"] || tc.topic || sid;
      teamCallEl.textContent = topic + " (" + sid.slice(0, 24) + "...)";
    } else {
      teamCallEl.textContent = "None (Idle)";
    }

    const fido = dash["fido-authenticator"] || dash.fidoAuthenticator;
    if (fido) {
      fidoNameEl.textContent = fido["authenticator-name"] || fido.authenticatorName || (fido.metadata && fido.metadata.description) || fido.label || "Hardware Key";
      fidoAaguidEl.textContent = fido.aaguid || (fido.metadata && fido.metadata.aaguid) || "unknown";
      fidoLevelEl.textContent = fido["certification-level"] || fido.certificationLevel || (fido.metadata && fido.metadata["certification-level"]) || fido.strength || "UNVERIFIED";
      fidoStatusBadge.textContent = "[ " + (fido["verification-status"] || fido.verificationStatus || "UNVERIFIED") + " ]";
      fidoWarningEl.textContent = fido.warning || "UNVERIFIED: MDS v3 validation pending full chain checks.";
    }

    // Render Offers
    const rawOffers = dash["pending-offers"] || dash.pendingOffers || [];
    const offers = Array.isArray(rawOffers) ? rawOffers : Object.values(rawOffers);
    offersCountBadge.textContent = offers.length + " Pending";
    if (offers.length === 0) {
      offersTable.style.display = "none";
      noOffersMsg.style.display = "block";
    } else {
      offersTable.style.display = "table";
      noOffersMsg.style.display = "none";
      offersTbody.innerHTML = "";
      offers.forEach(function (off) {
        const tr = document.createElement("tr");
        const id = off["offer-id"] || off.offerId;
        tr.innerHTML = "<td><code class='mono'>" + id + "</code></td>" +
          "<td><span class='mono'>" + (off["peer-id"] || off.peerId || "peer").slice(0, 16) + "...</span></td>" +
          "<td>" + (off["service-type"] || off.serviceType || "inference") + "</td>" +
          "<td>" + (off.burn || off["burn-amount"] || 100) + " ECH</td>" +
          "<td><span class='badge badge-warning'>PENDING</span></td>" +
          "<td style='text-align: right;'>" +
            "<button class='btn btn-success' style='margin-right: 6px;' data-approve='" + id + "'>Approve</button>" +
            "<button class='btn btn-danger' data-deny='" + id + "'>Deny</button>" +
          "</td>";
        offersTbody.appendChild(tr);
      });

      offersTbody.querySelectorAll("button[data-approve]").forEach(function (btn) {
        btn.onclick = function () {
          const id = btn.getAttribute("data-approve");
          writeLog("Human Anchor approving offer: " + id);
          const res = globalThis.BitechoBrowser.approveOffer(id);
          if (!res || res.ok === false) {
            writeLog("Approve offer failed: " + ((res && res.error) || "error"), res);
            return;
          }
          selectedSessionId = id;
          writeLog("Human Anchor approved offer: " + id);
          updateUI(res.dashboard);
          renderChatAndSessions(globalThis.BitechoBrowser.getStatus());
        };
      });

      offersTbody.querySelectorAll("button[data-deny]").forEach(function (btn) {
        btn.onclick = function () {
          const id = btn.getAttribute("data-deny");
          writeLog("Human Anchor denied offer: " + id);
          const res = globalThis.BitechoBrowser.denyOffer(id, "rejected-by-human");
          updateUI(res.dashboard);
          renderChatAndSessions(globalThis.BitechoBrowser.getStatus());
        };
      });
    }

    // Render Agents
    const rawAgents = dash["supervised-agents"] || dash.supervisedAgents || [];
    const agents = Array.isArray(rawAgents) ? rawAgents : Object.values(rawAgents);
    agentsCountBadge.textContent = agents.length + " Agents";
    if (agents.length === 0) {
      agentsTable.style.display = "none";
      noAgentsMsg.style.display = "block";
    } else {
      agentsTable.style.display = "table";
      noAgentsMsg.style.display = "none";
      agentsTbody.innerHTML = "";
      agents.forEach(function (ag) {
        const tr = document.createElement("tr");
        const aid = ag["agent-id"] || ag.agentId;
        const status = ag.status || "active";
        const isRevoked = status === "revoked";
        const badgeClass = isRevoked ? "badge-danger" : "badge-success";
        tr.innerHTML = "<td><strong>" + aid + "</strong></td>" +
          "<td><span class='mono'>" + (ag["hot-pubkey"] || ag.hotPubkey || ag.address || "").slice(0, 24) + "...</span></td>" +
          "<td><span class='badge " + badgeClass + "'>" + String(status).toUpperCase() + "</span></td>" +
          "<td>" + ((ag.permissions || []).join(", ") || "read, delegate") + "</td>" +
          "<td>" + (ag["activity-count"] || ag.activityCount || 0) + "</td>" +
          "<td style='text-align: right;'>" +
            (isRevoked ? "<span style='color: var(--text-muted); font-size: 0.8rem;'>Revoked</span>" :
              "<button class='btn btn-danger' data-revoke='" + aid + "'>Revoke DAC</button>") +
          "</td>";
        agentsTbody.appendChild(tr);
      });

      agentsTbody.querySelectorAll("button[data-revoke]").forEach(function (btn) {
        btn.onclick = function () {
          const aid = btn.getAttribute("data-revoke");
          writeLog("Human Anchor revoked DAC for agent: " + aid);
          const res = globalThis.BitechoBrowser.revokeAgentDac(aid, "manual-operator-revocation");
          updateUI(res.dashboard);
        };
      });
    }
  }

  let selectedSessionId = null;
  const knownOpenSessionIds = new Set();
  let lastRenderedChatJson = null;

  function syncPeerControlsForSelection(rawSessions, pubkeyToPetname) {
    if (!selectedSessionId || !rawSessions || !rawSessions[selectedSessionId]) return;
    const s = rawSessions[selectedSessionId];
    const peerHex = s.peer || s.peerId || "peer";
    const peerLabel = s.peer_petname || s["peer-petname"] || pubkeyToPetname[peerHex] || (peerHex.slice(0, 14) + "...");
    const peerHandle = pubkeyToPetname[peerHex] || peerHex;
    if (targetPeerInput && document.activeElement !== targetPeerInput) {
      targetPeerInput.value = peerHandle;
    }
    if (activePeerLabel) {
      activePeerLabel.textContent = "Peer: " + peerLabel + " (" + selectedSessionId.slice(0, 8) + ")";
    }
    if (chatInput) {
      chatInput.placeholder = "Type sealed message to " + peerLabel + "...";
    }
  }

  function renderChatAndSessions(status) {
    if (!status) return;
    const balanceEl = document.getElementById("balanceDisplay");
    if (balanceEl && status.balance != null) {
      balanceEl.textContent = Number(status.balance).toLocaleString() + " ECH";
    }

    // 1. Mesh Connection Status
    if (meshStatusBadge) {
      if (status.meshConnected) {
        const nodes = (status.connectedNodes && status.connectedNodes.length > 0)
          ? status.connectedNodes.join(", ")
          : "node1";
        meshStatusBadge.className = "badge badge-success";
        meshStatusBadge.textContent = "CONNECTED (" + nodes + ")";
        if (connectMeshBtn) {
          connectMeshBtn.textContent = "Mesh Connected";
          connectMeshBtn.disabled = true;
          connectMeshBtn.className = "btn btn-outline";
        }
      } else if (status.phase === "dialing" || status.phase === "connecting") {
        meshStatusBadge.className = "badge badge-warning";
        meshStatusBadge.textContent = "CONNECTING...";
        if (connectMeshBtn) {
          connectMeshBtn.textContent = "Connecting...";
          connectMeshBtn.disabled = true;
        }
      } else {
        meshStatusBadge.className = "badge badge-danger";
        meshStatusBadge.textContent = "DISCONNECTED";
        if (connectMeshBtn) {
          connectMeshBtn.textContent = "Connect Live Devnet Mesh";
          connectMeshBtn.disabled = false;
          connectMeshBtn.className = "btn btn-success";
        }
      }
    }

    // 2. Active Sealed Sessions
    const rawSessions = status.sessions || {};
    const petnames = status.petnames || {};
    const pubkeyToPetname = {};
    Object.keys(petnames).forEach(function (k) {
      pubkeyToPetname[petnames[k]] = k;
    });
    const sessEntries = Array.isArray(rawSessions)
      ? rawSessions
      : Object.entries(rawSessions).map(function (entry) {
          return Object.assign({ sessionId: entry[0] }, entry[1]);
        });

    const openEntries = sessEntries.filter(function (s) {
      return String(s.state || s.status || "open").toUpperCase() === "OPEN";
    });
    let newlyOpenedId = null;
    openEntries.forEach(function (s) {
      if (s.sessionId && !knownOpenSessionIds.has(s.sessionId)) {
        knownOpenSessionIds.add(s.sessionId);
        newlyOpenedId = s.sessionId;
      }
    });
    if (newlyOpenedId) {
      selectedSessionId = newlyOpenedId;
    }
    if (selectedSessionId && !rawSessions[selectedSessionId]) {
      selectedSessionId = null;
    }
    if (!selectedSessionId && openEntries.length > 0) {
      selectedSessionId = openEntries[openEntries.length - 1].sessionId;
    }
    syncPeerControlsForSelection(rawSessions, pubkeyToPetname);

    if (sessionsCountBadge) {
      sessionsCountBadge.textContent = openEntries.length + " Open / " + sessEntries.length + " Total";
    }

    if (sessionsList && noSessionsMsg) {
      if (sessEntries.length === 0) {
        noSessionsMsg.style.display = "block";
        sessionsList.style.display = "none";
      } else {
        noSessionsMsg.style.display = "none";
        sessionsList.style.display = "flex";
        sessionsList.style.flexDirection = "column";
        sessionsList.style.gap = "6px";
        sessionsList.innerHTML = "";
        sessEntries.forEach(function (s) {
          const item = document.createElement("div");
          const isSelected = s.sessionId && s.sessionId === selectedSessionId;
          const st = String(s.state || s.status || "open").toUpperCase();
          const badgeClass = st === "OPEN" ? "badge-success" : "badge-warning";
          const peerHex = s.peer || s.peerId || "peer";
          const peerLabel = s.peer_petname || s["peer-petname"] || pubkeyToPetname[peerHex] || (peerHex.slice(0, 14) + "...");
          item.style.cssText = (isSelected
            ? "background: #1e1b4b; padding: 6px 10px; border-radius: 4px; border: 1px solid #6366f1; "
            : "background: #16161c; padding: 6px 10px; border-radius: 4px; border: 1px solid #282834; ") +
            "display: flex; justify-content: space-between; align-items: center; cursor: pointer;";
          item.title = "Click to select session " + (s.sessionId || "") + " (" + st + ")";
          item.innerHTML = "<div>" +
            "<strong style='color: #a5b4fc;'>" + (s.sessionId ? s.sessionId.slice(0, 10) + "..." : "session") + "</strong> " +
            "<span style='color: var(--text-muted); font-size: 0.72rem;'>→ " + peerLabel + "</span>" +
            "</div>" +
            "<div style='display: flex; gap: 6px; align-items: center;'>" +
            "<span class='badge " + badgeClass + "' style='font-size: 0.65rem;'>" + st + "</span>" +
            "<button class='btn btn-outline' data-close-session='" + (s.sessionId || "") + "' title='Remove session' style='padding: 1px 6px; font-size: 0.68rem; line-height: 1.2;'>×</button>" +
            "</div>";
          item.onclick = function (ev) {
            if (ev.target && ev.target.getAttribute && ev.target.getAttribute("data-close-session")) {
              return;
            }
            selectedSessionId = s.sessionId;
            syncPeerControlsForSelection(rawSessions, pubkeyToPetname);
            renderChatAndSessions(globalThis.BitechoBrowser.getStatus());
          };
          const closeBtn = item.querySelector("button[data-close-session]");
          if (closeBtn) {
            closeBtn.onclick = function (ev) {
              ev.stopPropagation();
              const sid = closeBtn.getAttribute("data-close-session");
              if (sid && typeof globalThis.BitechoBrowser.closeSession === "function") {
                if (selectedSessionId === sid) selectedSessionId = null;
                globalThis.BitechoBrowser.closeSession(sid);
                writeLog("Removed session: " + sid.slice(0, 12) + "...");
              }
            };
          }
          sessionsList.appendChild(item);
        });
      }
    }

    // 3. Chat History Thread
    if (chatMessages) {
      const history = status.chatHistory || [];
      const chatJson = JSON.stringify({ h: history, c: Boolean(status.meshConnected) });
      if (chatJson !== lastRenderedChatJson) {
        lastRenderedChatJson = chatJson;
        if (history.length === 0) {
          chatMessages.innerHTML = "<div style='color: var(--text-muted); text-align: center; margin-top: 40px; font-style: italic;'>" +
            (status.meshConnected ? "Channel ready. Send a sealed message to peer." : "Connect to devnet mesh and open a sealed channel to message peer.") +
            "</div>";
        } else {
          chatMessages.innerHTML = "";
          history.forEach(function (msg) {
            const msgDiv = document.createElement("div");
            const isOutgoing = msg.direction === "outgoing";
            msgDiv.style.cssText = "display: flex; flex-direction: column; margin-bottom: 8px; align-items: " + (isOutgoing ? "flex-end" : "flex-start") + ";";

            const bubble = document.createElement("div");
            bubble.style.cssText = "max-width: 80%; padding: 8px 12px; border-radius: 6px; font-size: 0.8rem; word-break: break-word; " +
              (isOutgoing ? "background: #312e81; color: #e0e7ff; border: 1px solid #4338ca;" : "background: #064e3b; color: #d1fae5; border: 1px solid #047857;");

            const header = document.createElement("div");
            header.style.cssText = "font-size: 0.68rem; opacity: 0.75; margin-bottom: 2px; display: flex; justify-content: space-between; gap: 8px;";
            const timeStr = msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : "";
            const sidTag = msg.sessionId ? " (" + String(msg.sessionId).slice(0, 6) + ")" : "";
            const senderLabel = isOutgoing
              ? ("You → " + (msg.peer || "Peer") + sidTag)
              : ((msg.peer || "Peer") + sidTag);
            header.innerHTML = "<span>" + senderLabel + "</span><span>" + timeStr + "</span>";

            const body = document.createElement("div");
            body.textContent = msg.text || "";

            bubble.appendChild(header);
            bubble.appendChild(body);
            msgDiv.appendChild(bubble);
            chatMessages.appendChild(msgDiv);
          });
          chatMessages.scrollTop = chatMessages.scrollHeight;
        }
      }
    }
  }

  if (connectMeshBtn) {
    connectMeshBtn.onclick = function () {
      writeLog("Connecting to live Bitecho Devnet Mesh via WebRTC DataChannel (node1: 35.212.129.138:5010)...");
      try {
        const res = globalThis.BitechoBrowser.connectMesh();
        writeLog("Dialing mesh node1:", res);
      } catch (err) {
        writeLog("Mesh connection error: " + (err.message || err));
      }
    };
  }

  if (targetPeerInput) {
    targetPeerInput.oninput = function () {
      selectedSessionId = null;
      const val = targetPeerInput.value.trim() || "axiom";
      if (activePeerLabel) activePeerLabel.textContent = "Peer: " + val;
    };
  }

  if (openChannelBtn) {
    openChannelBtn.onclick = function () {
      const target = (targetPeerInput && targetPeerInput.value.trim()) || "axiom";
      writeLog("Initiating signed channel offer to: " + target);
      try {
        const res = globalThis.BitechoBrowser.openChannel(target);
        writeLog("Channel offer sent:", res);
      } catch (err) {
        writeLog("Failed to open channel: " + (err.message || err));
      }
    };
  }

  function doSendMessage() {
    if (!chatInput) return;
    const text = chatInput.value.trim();
    if (!text) return;
    const target = (targetPeerInput && targetPeerInput.value.trim()) || "axiom";
    writeLog("Sending sealed message to " + target + (selectedSessionId ? " (session " + selectedSessionId.slice(0, 8) + "...)" : "") + ": " + text);
    try {
      const res = globalThis.BitechoBrowser.sendMessage(target, text, selectedSessionId);
      if (!res || res.ok === false) {
        writeLog("Send message failed: " + ((res && res.error) || "no-open-session-for-peer"), res);
        return;
      }
      writeLog("Message sent:", res);
      chatInput.value = "";
    } catch (err) {
      writeLog("Send message error: " + (err.message || err));
    }
  }

  if (sendMessageBtn) {
    sendMessageBtn.onclick = doSendMessage;
  }

  if (chatInput) {
    chatInput.onkeydown = function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        doSendMessage();
      }
    };
  }

  if (globalThis.BitechoBrowser) {
    writeLog("BitechoBrowser v" + globalThis.BitechoBrowser.version + " initialized.");
    globalThis.BitechoBrowser.initNode();
    const initialDash = globalThis.BitechoBrowser.initAnchor();
    updateUI(initialDash);
    if (typeof globalThis.BitechoBrowser.loadStateFromIndexedDB === "function") {
      Promise.resolve(globalThis.BitechoBrowser.loadStateFromIndexedDB()).then(function (restored) {
        const restoredPub = restored && (restored.pubkey || (restored["light-state"] && restored["light-state"].pubkey));
        if (restoredPub) {
          writeLog("Restored persisted public identity from IndexedDB (tap Recover from YubiKey to unlock signing):", {
            pubkey: restoredPub,
            address: restored.address,
            hardwareLocked: restored.hardwareLocked
          });
          updateUI(globalThis.BitechoBrowser.getAnchorDashboard());
          renderChatAndSessions(globalThis.BitechoBrowser.getStatus());
        }
      }).catch(function () {});
    }
    globalThis.BitechoBrowser.onStateChange(function (st) {
      renderChatAndSessions(st);
      updateUI(globalThis.BitechoBrowser.getAnchorDashboard());
    });
    renderChatAndSessions(globalThis.BitechoBrowser.getStatus());
  } else {
    log.textContent = "Error: BitechoBrowser bundle failed to load.";
  }

  document.getElementById("runAnchorDemoBtn").onclick = function () {
    writeLog("Executing complete Human Anchor End-to-End Demo...");
    const res = globalThis.BitechoBrowser.runAnchorEndToEndDemo();
    writeLog("Anchor Demo Result:", res);
    updateUI(res.dashboard);
  };

  document.getElementById("runSubnetDemoBtn").onclick = function () {
    writeLog("Executing Browser Subnet Demo...");
    const res = globalThis.BitechoBrowser.runSubnetDemo();
    writeLog("Subnet Demo Result:", res);
  };

  document.getElementById("runZeroBurnSubnetBtn").onclick = function () {
    writeLog("Executing Zero-Burn Team Subnet Demo...");
    const res = globalThis.BitechoBrowser.runZeroBurnSubnetDemo();
    writeLog("Zero-Burn Subnet Result:", res);
  };

  document.getElementById("runFederationBtn").onclick = function () {
    writeLog("Executing Domain Federation Demo...");
    const res = globalThis.BitechoBrowser.runFederationDemo();
    writeLog("Domain Federation Result:", res);
  };

  document.getElementById("simOfferBtn").onclick = function () {
    writeLog("Simulating incoming service offer...");
    const dash = globalThis.BitechoBrowser.queueOffer();
    updateUI(dash);
    writeLog("Simulated incoming offer queued on anchor.");
  };

  async function handleRegisterYubiKey() {
    writeLog("Prompting hardware authenticator (WebAuthn create)...");
    try {
      const cred = await globalThis.BitechoBrowser.createDiscoverableCredential();
      const rec = globalThis.BitechoBrowser.recoverFromYubiKey(cred);
      if (!rec || rec.ok === false) {
        writeLog("YubiKey registration failed: " + ((rec && rec.error) || "recovery-failed"));
        return;
      }
      const dash = globalThis.BitechoBrowser.getAnchorDashboard();
      updateUI(dash);
      renderChatAndSessions(globalThis.BitechoBrowser.getStatus());
      writeLog("Anchor initialized from hardware YubiKey:", {
        pubkey: (dash.identity && dash.identity["anchor-pubkey"]) || "unknown",
        address: (dash.identity && dash.identity.address) || "unknown",
        fidoStatus: (dash["fido-authenticator"] && dash["fido-authenticator"]["verification-status"]) || "UNVERIFIED"
      });
    } catch (err) {
      writeLog("YubiKey registration error: " + (err.message || err));
    }
  }

  async function handleRecoverYubiKey() {
    writeLog("[P-WEB-1 diag] Recover handler entered; prompting hardware authenticator (WebAuthn get)...");
    try {
      const cred = await globalThis.BitechoBrowser.getDiscoverableCredential();
      writeLog("[P-WEB-1 diag] Stage 1 getDiscoverableCredential resolved:", {
        credType: cred === null ? "null" : typeof cred,
        credKeys: (cred && typeof cred === "object") ? Object.keys(cred) : [],
        diagnostics: (cred && cred.diagnostics) || null
      });
      const rec = globalThis.BitechoBrowser.recoverFromYubiKey(cred);
      if (!rec || rec.ok === false) {
        const failReason = (rec && (rec["failure-reason"] || rec.error)) || "recovery-failed";
        const failStage = (rec && rec["failure-stage"]) || "unknown";
        writeLog("YubiKey recovery failed [" + failStage + "]: " + failReason, (rec && rec.diagnostics) || null);
        return;
      }
      if (rec.diagnostics) {
        writeLog("[P-WEB-1 diag] Stage 2 recoverFromYubiKey diagnostics:", rec.diagnostics);
      }
      const dash = globalThis.BitechoBrowser.getAnchorDashboard();
      updateUI(dash);
      renderChatAndSessions(globalThis.BitechoBrowser.getStatus());
      writeLog("Anchor recovered from hardware YubiKey:", {
        pubkey: (dash.identity && dash.identity["anchor-pubkey"]) || "unknown",
        address: (dash.identity && dash.identity.address) || "unknown",
        fidoStatus: (dash["fido-authenticator"] && dash["fido-authenticator"]["verification-status"]) || "UNVERIFIED"
      });
    } catch (err) {
      writeLog("YubiKey recovery error: " + (err.message || err));
    }
  }

  document.getElementById("registerYubiKeyBtn").onclick = handleRegisterYubiKey;
  document.getElementById("recoverYubiKeyBtn").onclick = handleRecoverYubiKey;
  const regCardBtn = document.getElementById("registerYubiKeyCardBtn");
  if (regCardBtn) regCardBtn.onclick = handleRegisterYubiKey;
  const recCardBtn = document.getElementById("recoverYubiKeyCardBtn");
  if (recCardBtn) recCardBtn.onclick = handleRecoverYubiKey;
  const saveIdbBtn = document.getElementById("saveStateIdbBtn");
  if (saveIdbBtn) {
    saveIdbBtn.onclick = function () {
      Promise.resolve(globalThis.BitechoBrowser.saveStateToIndexedDB()).then(function (res) {
        const st = globalThis.BitechoBrowser.getStatus();
        writeLog("Saved public identity & address to IndexedDB:", {
          address: st && st.address,
          pubkey: st && st.pubkey,
          result: res
        });
      }).catch(function (err) {
        writeLog("Failed to save identity to IndexedDB: " + (err.message || err));
      });
    };
  }

  document.getElementById("spawnAgentBtn").onclick = function () {
    const aid = "agent-" + Math.floor(Math.random() * 900 + 100);
    const dummyHot = "302a300506032b6570032100" + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join("");
    writeLog("Registering supervised agent with DAC: " + aid);
    const res = globalThis.BitechoBrowser.superviseAgent(aid, dummyHot, ["inference", "relay"]);
    writeLog("Agent registered:", {
      agentId: aid,
      status: res.status || "active"
    });
    updateUI(res.dashboard);
  };

  document.getElementById("resetAnchorBtn").onclick = function () {
    writeLog("Resetting Human Anchor state...");
    const dash = globalThis.BitechoBrowser.initAnchor();
    updateUI(dash);
  };

  keyModeSel.onchange = function () {
    const mode = keyModeSel.value;
    writeLog("Key mode updated: " + mode);
    if (mode === "webcrypto-non-extractable") {
      globalThis.BitechoBrowser.generateNonExtractableKey();
      writeLog("Generated non-extractable WebCrypto key spec:", {
        keyMode: "webcrypto-non-extractable",
        status: "ready"
      });
    } else if (mode === "yubikey-discoverable") {
      globalThis.BitechoBrowser.registerYubiKey();
      writeLog("YubiKey discoverable options configured:", {
        keyMode: "yubikey-discoverable",
        status: "configured"
      });
    }
    updateUI(globalThis.BitechoBrowser.getAnchorDashboard());
  };

  const sendSubnetBroadcastBtn = document.getElementById("sendSubnetBroadcastBtn");
  if (sendSubnetBroadcastBtn) {
    sendSubnetBroadcastBtn.onclick = function () {
      const subEl = document.getElementById("subnetBroadcastTarget");
      const txtEl = document.getElementById("subnetBroadcastInput");
      const sub = (subEl && subEl.value.trim()) || "chat/simon-nexus-axiom";
      const txt = (txtEl && txtEl.value.trim()) || "";
      if (!txt) return;
      writeLog("Broadcasting to subnet " + sub + ": " + txt);
      const res = globalThis.BitechoBrowser.broadcastMessage(txt, sub);
      writeLog("Subnet broadcast result:", res);
      if (txtEl && res && res.ok) txtEl.value = "";
    };
  }

  const consentBipBtn = document.getElementById("consentBipBtn");
  if (consentBipBtn) {
    consentBipBtn.onclick = function () {
      const bipId = (document.getElementById("bipIdInput") && document.getElementById("bipIdInput").value.trim()) || "BIP-006";
      const circle = (document.getElementById("bipCircleSelect") && document.getElementById("bipCircleSelect").value) || "anchor-agent-users";
      writeLog("Signing Sociocratic BIP consent for " + bipId + " (" + circle + ")...");
      const res = globalThis.BitechoBrowser.consentBip(bipId, circle, "bitecho.org/dev");
      writeLog("BIP consent result:", res);
    };
  }

  const checkBipStatusBtn = document.getElementById("checkBipStatusBtn");
  if (checkBipStatusBtn) {
    checkBipStatusBtn.onclick = function () {
      const bipId = (document.getElementById("bipIdInput") && document.getElementById("bipIdInput").value.trim()) || "BIP-006";
      const res = globalThis.BitechoBrowser.getBipStatus(bipId, "bitecho.org/dev");
      writeLog("BIP status for " + bipId + ":", res);
    };
  }

  const claimFaucetBtn = document.getElementById("claimFaucetBtn");
  if (claimFaucetBtn) {
    claimFaucetBtn.onclick = function () {
      const claimant = document.getElementById("faucetClaimantInput") && document.getElementById("faucetClaimantInput").value.trim();
      writeLog("Requesting hardware-key sponsored faucet drip (1,000,000 ECH)...");
      Promise.resolve(globalThis.BitechoBrowser.claimHardwareKeyFaucet({ claimantPubkey: claimant || null })).then(function (res) {
        writeLog("Hardware-key faucet claim result:", res);
        updateUI(globalThis.BitechoBrowser.getAnchorDashboard());
        renderChatAndSessions(globalThis.BitechoBrowser.getStatus());
      }).catch(function (err) {
        writeLog("Faucet claim error: " + (err.message || err));
      });
    };
  }
})();
