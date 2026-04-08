// Xalgorix Web UI — WebSocket client and DOM renderer
(function () {
    'use strict';

    // Auth check — redirect to login if session expired
    fetch('/api/auth/status').then(r => r.json()).then(data => {
        if (data.auth_enabled && !data.authenticated) {
            window.location.reload(); // Server will serve login page
        }
    }).catch(() => {});

    // Intercept all fetch calls to handle 401 globally
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        return originalFetch.apply(this, args).then(response => {
            if (response.status === 401 && !args[0].toString().includes('/api/auth/')) {
                window.location.reload();
            }
            return response;
        });
    };

    let ws = null;
    let scanRunning = false;
    let iterCount = 0;
    let toolCount = 0;
    let vulnCount = 0;
    let eventCount = 0;
    let scanStart = null;
    let autoScroll = true;
    const toolUsage = {};

    // SPA routing state
    let currentView = 'dashboard'; // 'dashboard' or 'scan'
    let currentInstanceID = null;
    let instancePollTimer = null;

    // Simple markdown to HTML converter
    function mdToHtml(text) {
        if (!text) return '';
        let html = text;
        // Escape HTML first
        html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        // Convert markdown
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
        html = html.replace(/`(.+?)`/g, '<code>$1</code>');
        html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^### (.+)$/gm, '<h4>$1</h4>');
        html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
        html = html.replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>');
        html = html.replace(/\n\n/g, '</p><p>');
        html = html.replace(/\n/g, '<br>');
        // Wrap lists
        html = html.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');
        return '<p>' + html + '</p>';
    }

    // Multi-target queue
    let loadedTargets = [];
    let currentTargetIdx = 0;
    let totalTargets = 0;
    let currentSubIdx = 0;
    let totalSubTargets = 0;
    let parentTarget = '';

    const TOOL_ICONS = {
        terminal_execute: '⚡', browser_action: '🌐', view_file: '📝', create_file: '📝',
        str_replace: '📝', insert_line: '📝', list_files: '📄', search_files: '🔍',
        proxy_request: '🔗', list_proxy_requests: '🔗', python_action: '🐍',
        web_search: '🔍', add_note: '📌', report_vulnerability: '🐛',
        create_agent: '🤖', finish: '✅',
    };

    const LLM_PROVIDERS = {
        openai: { model: 'gpt-4o', prefix: 'openai', base: 'https://api.openai.com/v1' },
        anthropic: { model: 'claude-sonnet-4.6', prefix: 'anthropic', base: 'https://api.anthropic.com/' },
        google: { model: 'gemini-2.0-flash', prefix: 'google', base: 'https://generativelanguage.googleapis.com/v1beta/openai/' },
        deepseek: { model: 'deepseek-chat-v3', prefix: 'deepseek', base: 'https://api.deepseek.com/' },
        groq: { model: 'llama-3.3-70b', prefix: 'groq', base: 'https://api.groq.com/openai/v1' },
        minimax: { model: 'MiniMax-M2.7', prefix: 'minimax', base: 'https://api.minimax.io/' },
        ollama: { model: 'llama-3.3-70b-instruct', prefix: 'ollama', base: 'http://localhost:11434/v1' },
        custom: { model: '', prefix: '', base: '' },
    };

    // ── WebSocket with Improved Reconnection ────────────────
    let wsReconnectAttempts = 0;
    let wsReconnectDelay = 1000;
    const wsMaxReconnectDelay = 30000;
    let wsReconnecting = false;
    let isConnecting = false; // prevent duplicate connection attempts
    let wsReconnectTimer = null; // track scheduled reconnect to cancel on manual reconnect
    
    function connect() {
        // Prevent duplicate connection attempts
        if (isConnecting) return;
        if (ws && ws.readyState === WebSocket.OPEN) return;
        
        isConnecting = true;
        
        // Close old WebSocket if it exists (prevent zombie connections)
        if (ws) {
            try {
                ws.onclose = null; // prevent recursive reconnect
                ws.onerror = null;
                ws.onmessage = null;
                ws.close();
            } catch (e) { /* ignore close errors on dead socket */ }
            ws = null;
        }
        
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${proto}//${location.host}/ws`);
        
        ws.onopen = () => {
            console.log('WS connected');
            wsReconnectAttempts = 0;
            wsReconnectDelay = 1000;
            wsReconnecting = false;
            isConnecting = false;
            updateConnectionStatus('connected');
            
            // Re-subscribe if viewing an instance
            if (currentView === 'scan' && currentInstanceID) {
                ws.send(JSON.stringify({ subscribe: currentInstanceID }));
            }
        };
        
        ws.onclose = (e) => {
            console.log('WS disconnected', e.code, e.reason);
            isConnecting = false;
            wsReconnecting = true;
            updateConnectionStatus('disconnected');
            
            // Don't reconnect if closed cleanly by server
            if (e.code === 1000) {
                hideReconnectIndicator();
                return;
            }
            
            // Exponential backoff
            wsReconnectAttempts++;
            const delay = Math.min(wsReconnectDelay * Math.pow(1.5, wsReconnectAttempts - 1), wsMaxReconnectDelay);
            console.log(`WS reconnecting in ${delay}ms (attempt ${wsReconnectAttempts})`);
            showReconnectIndicator(wsReconnectAttempts);
            
            wsReconnectTimer = setTimeout(connect, delay);
        };
        
        ws.onerror = (e) => {
            console.error('WS error', e);
            isConnecting = false;
            updateConnectionStatus('error');
        };
        
        ws.onmessage = (e) => {
            try { handleEvent(JSON.parse(e.data)); } catch (err) { console.error('Parse error', err); }
        };
    }
    
    function updateConnectionStatus(status) {
        // Create status indicator if not exists
        let indicator = document.getElementById('ws-status');
        if (!indicator) {
            const header = document.querySelector('.header-stats');
            indicator = document.createElement('div');
            indicator.id = 'ws-status';
            indicator.style.cssText = 'width:8px;height:8px;border-radius:50%;margin-right:8px;';
            header.insertBefore(indicator, header.firstChild);
        }
        
        switch(status) {
            case 'connected':
                indicator.style.background = '#22C55E';
                indicator.style.boxShadow = '0 0 6px #22C55E';
                hideReconnectIndicator();
                break;
            case 'disconnected':
                indicator.style.background = '#F59E0B';
                indicator.style.boxShadow = '0 0 6px #F59E0B';
                break;
            case 'error':
                indicator.style.background = '#EF4444';
                indicator.style.boxShadow = '0 0 6px #EF4444';
                break;
        }
    }
    
    // Reconnection indicator
    function showReconnectIndicator(attempt) {
        let el = document.getElementById('ws-reconnect-bar');
        if (!el) {
            el = document.createElement('div');
            el.id = 'ws-reconnect-bar';
            el.className = 'ws-reconnecting';
            document.body.appendChild(el);
        }
        el.innerHTML = `<div class="spinner"></div> Reconnecting... (attempt ${attempt})`;
        el.style.display = 'flex';
    }
    
    function hideReconnectIndicator() {
        const el = document.getElementById('ws-reconnect-bar');
        if (el) el.style.display = 'none';
    }
    
    // Function to manually reconnect
    window.reconnectWebSocket = function() {
        if (wsReconnectTimer) { clearTimeout(wsReconnectTimer); wsReconnectTimer = null; }
        isConnecting = false; // reset flag so connect() can proceed
        wsReconnectAttempts = 0;
        wsReconnectDelay = 1000;
        connect();
    };

    // ── Event Handler ──────────────────────────────────────
    function handleEvent(evt, replay) {
        // During replay, skip dashboard-level filtering
        if (!replay) {
            // Dashboard-level events
            if (evt.type === 'instance_started' || evt.type === 'instance_updated') {
                if (currentView === 'dashboard') refreshInstances();
                return;
            }
            if (evt.type === 'error' && currentView === 'dashboard') {
                showToast('⚠️ ' + evt.content, 'error');
                return;
            }

            // If we're on dashboard, ignore scan-specific events
            if (currentView === 'dashboard') return;
        }

        // ── SCAN VIEW EVENTS ──
        console.log('Received event:', evt.type, evt);
        
        // Update token counter from any event that carries it
        if (evt.total_tokens && evt.total_tokens > 0) {
            const formatted = evt.total_tokens >= 1000000
                ? (evt.total_tokens / 1000000).toFixed(1) + 'M'
                : evt.total_tokens >= 1000
                ? (evt.total_tokens / 1000).toFixed(1) + 'K'
                : String(evt.total_tokens);
            const el = document.getElementById('stat-tokens');
            if (el) {
                el.textContent = formatted;
                popStat('stat-tokens');
            }
        }

        eventCount++;
        hideEmptyState();

        switch (evt.type) {
            case 'queue_started':
                setStatus('running', 'SCANNING');
                totalTargets = evt.total_targets || 1;
                if (totalTargets > 1) showQueueBar();
                addFeedItem(renderBanner('🚀', evt.content));
                showToast('🚀 Scan started', 'info');
                break;

            case 'target_started':
                currentTargetIdx = evt.target_index || 1;
                // Only update totalTargets from real top-level events (not subdomain events)
                if (evt.total_targets && evt.total_targets > 0) {
                    totalTargets = evt.total_targets;
                }
                // Track sub-target progress for wildcard scanning
                if (evt.sub_target_index && evt.sub_target_total) {
                    currentSubIdx = evt.sub_target_index;
                    totalSubTargets = evt.sub_target_total;
                    parentTarget = evt.parent_target || '';
                    updateQueueBar(currentTargetIdx, totalTargets, evt.target, currentSubIdx, totalSubTargets);
                } else {
                    currentSubIdx = 0;
                    totalSubTargets = 0;
                    parentTarget = '';
                    updateQueueBar(currentTargetIdx, totalTargets, evt.target);
                }
                if (totalTargets > 1 || totalSubTargets > 0) showQueueBar();
                addFeedItem(renderTargetBanner(evt.target));
                if (evt.agent_id) {
                    history.pushState(null, '', '/' + evt.agent_id);
                }
                break;

            case 'target_completed':
                addFeedItem(renderBanner('✅', `Completed: ${evt.content || evt.target}`, 'success'));
                break;

            case 'queue_finished':
                scanRunning = false;
                setStatus('finished', 'COMPLETED');
                toggleButtons(false);
                hideQueueBar();
                hideChatInput();
                addFeedItem(renderBanner('🏁', evt.content || 'All targets completed', 'success'));
                showToast('🏁 All targets completed', 'success');
                break;

            case 'report_ready':
                showReportButton(evt.report_url || evt.content);
                addFeedItem(renderBanner('📄', 'Report ready! Click to download.', 'success'));
                break;

            case 'scan_started':
                setStatus('running', 'SCANNING');
                addFeedItem(renderBanner('🚀', evt.content));
                break;

            case 'thinking':
                iterCount++;
                const iterEl = document.getElementById('stat-iter');
                if (iterEl) iterEl.textContent = iterCount;
                popStat('stat-iter');
                addFeedItem(renderThinking(evt.content), true);
                break;

            case 'tool_call':
                toolCount++;
                const toolEl = document.getElementById('stat-tools');
                if (toolEl) toolEl.textContent = toolCount;
                popStat('stat-tools');
                toolUsage[evt.tool_name] = (toolUsage[evt.tool_name] || 0) + 1;
                updateToolStats();
                addFeedItem(renderToolCall(evt));
                break;

            case 'tool_result': {
                const resultOutput = evt.error || evt.output || '';
                // Skip empty/whitespace-only results entirely
                if (!resultOutput.trim()) break;
                
                // Only merge if the LAST element in feed is a result from same tool
                const feedEl = document.getElementById('feed-body');
                const lastChild = feedEl ? feedEl.lastElementChild : null;
                const isPartialUpdate = lastChild 
                    && lastChild.classList.contains('event-result') 
                    && lastChild._toolName === evt.tool_name;
                
                if (isPartialUpdate) {
                    const isLong = resultOutput.length > 1200;
                    const truncated = isLong ? resultOutput.slice(0, 1200) + '\n... (click to expand)' : resultOutput;
                    lastChild.textContent = truncated;
                    lastChild.className = `event event-result${evt.error ? ' error' : ''}${isLong ? ' expandable' : ''}`;
                    if (isLong) {
                        lastChild._fullText = resultOutput;
                        lastChild._truncated = truncated;
                    }
                    if (autoScroll) feedEl.scrollTop = feedEl.scrollHeight;
                } else {
                    const resultEl = renderToolResult(evt);
                    if (resultEl.textContent.trim()) {
                        resultEl._toolName = evt.tool_name;
                        addFeedItem(resultEl);
                    }
                }
                // Real-time vuln rendering
                if (evt.vulns && evt.vulns.length > 0) {
                    vulnCount += evt.vulns.length;
                    const vulnEl = document.getElementById('stat-vulns');
                    if (vulnEl) vulnEl.textContent = vulnCount;
                    popStat('stat-vulns');
                    renderVulns(evt.vulns);
                }
                break;
            }

            case 'message':
                if (evt.content && evt.content.trim() && !hasToolTags(evt.content)) {
                    addFeedItem(renderMessage(evt.content));
                }
                break;

            case 'error':
                addFeedItem(renderError(evt.content));
                showToast('⚠️ ' + (evt.content || 'Error').slice(0, 80), 'error');
                break;

            case 'finished':
                if (evt.vulns && evt.vulns.length > 0) {
                    vulnCount += evt.vulns.length;
                    popStat('stat-vulns');
                    renderVulns(evt.vulns);
                }
                // Only mark scan as complete if this is a single-target scan
                // with no queue. For multi-target/wildcard scans, queue_finished
                // handles the final state transition.
                if (totalTargets <= 1 && totalSubTargets <= 0) {
                    scanRunning = false;
                    setStatus('finished', 'COMPLETED');
                    toggleButtons(false);
                    hideChatInput();
                    addFeedItem(renderFinished(evt.content));
                    showToast('✅ Scan completed', 'success');
                }
                break;

            case 'stopped':
                scanRunning = false;
                setStatus('idle', 'STOPPED');
                toggleButtons(false);
                hideQueueBar();
                hideChatInput();
                addFeedItem(renderError(evt.content || 'Scan stopped by user'));
                showToast('■ Scan stopped', 'warning');
                break;
        }
    }

    // ── Renderers ──────────────────────────────────────────
    function renderBanner(icon, content, type = 'accent') {
        const el = document.createElement('div');
        el.className = 'event event-finished';
        if (type === 'success') {
            el.style.background = 'var(--success-subtle)';
        }
        el.innerHTML = `${icon} ${esc(content)}`;
        return el;
    }

    function renderTargetBanner(target) {
        const el = document.createElement('div');
        el.className = 'event event-target';
        el.innerHTML = `🎯 Scanning: ${esc(target)}`;
        return el;
    }

    function renderThinking(content) {
        const el = document.createElement('div');
        el.className = 'event event-think';
        el.innerHTML = `<div class="typing"><span></span><span></span><span></span></div> ${esc(content)}`;
        return el;
    }

    function renderToolCall(evt) {
        const el = document.createElement('div');
        el.className = 'event event-tool';
        const icon = TOOL_ICONS[evt.tool_name] || '🔧';
        const timeStr = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '';
        let argsHTML = '';
        if (evt.tool_args && Object.keys(evt.tool_args).length > 0) {
            const argsText = Object.entries(evt.tool_args)
                .map(([k, v]) => `${k}: ${typeof v === 'string' && v.length > 200 ? v.slice(0, 200) + '...' : v}`)
                .join('\n');
            argsHTML = `<div class="event-tool-args">${esc(argsText)}</div>`;
        }
        el.innerHTML = `
            <div class="event-tool-header">
                <span class="event-tool-icon">${icon}</span>
                <span class="event-tool-name">${esc(evt.tool_name)}</span>
                <span class="event-tool-time">${timeStr}</span>
            </div>${argsHTML}`;
        return el;
    }

    function renderToolResult(evt) {
        const el = document.createElement('div');
        const output = evt.error || evt.output || '';
        if (!output.trim()) return el; // skip empty results
        const isLong = output.length > 1200;
        const truncated = isLong ? output.slice(0, 1200) + '\n... (click to expand)' : output;
        el.className = `event event-result${evt.error ? ' error' : ''}${isLong ? ' expandable' : ''}`;
        el.textContent = truncated;
        if (isLong) {
            el._fullText = output;
            el._truncated = truncated;
            el._expanded = false;
            el.addEventListener('click', function() {
                this._expanded = !this._expanded;
                this.textContent = this._expanded ? this._fullText : this._truncated;
                this.classList.toggle('expanded', this._expanded);
            });
        }
        return el;
    }

    function renderMessage(content) {
        const el = document.createElement('div');
        el.className = 'event event-message';
        // Render markdown in messages
        el.innerHTML = mdToHtml(content);
        return el;
    }

    function renderError(content) {
        const el = document.createElement('div');
        el.className = 'event event-error';
        el.innerHTML = `⚠️ ${esc(content)}`;
        return el;
    }

    function renderFinished(content) {
        const el = document.createElement('div');
        el.className = 'event event-finished';
        el.innerHTML = `✅ <strong>Scan Complete:</strong> ${esc((content || '').slice(0, 500))}`;
        return el;
    }

    function renderVulns(vulns) {
        const list = document.getElementById('vuln-list');
        const empty = list.querySelector('.empty-state');
        if (empty) list.innerHTML = '';
        
        const countEl = document.getElementById('vuln-count');
        if (countEl) countEl.textContent = vulnCount;
        
        vulns.forEach((v) => {
            const li = document.createElement('li');
            li.className = `vuln-item ${v.severity.toLowerCase()}`;
            li._vulnData = v;
            li.innerHTML = `
                <div class="vuln-header" style="cursor:pointer">
                    <span class="vuln-severity-dot ${v.severity.toLowerCase()}"></span>
                    <span class="vuln-title-text">${esc(v.title)}</span>
                    <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);margin-left:auto;margin-right:8px">${v.cvss ? v.cvss.toFixed(1) : ''}</span>
                    <span class="vuln-badge ${v.severity.toLowerCase()}">${v.severity.toUpperCase()}</span>
                </div>
            `;
            // Store vuln data for delegated event handler
            li.addEventListener('click', function() {
                openVulnModal(v);
            });
            list.appendChild(li);
        });
    }

    // Toggle vuln expand - now opens modal
    window.toggleVuln = function(el, vulnData) {
        // Store vuln data on the element if not already there
        if (vulnData) {
            el.closest('.vuln-item')._vulnData = vulnData;
        }
        const vulnItem = el.closest('.vuln-item');
        const v = vulnItem._vulnData;
        if (v) {
            openVulnModal(v);
        }
    };

    // Modal functions
    window.openVulnModal = function(v) {
        const modal = document.getElementById('vuln-modal');
        const titleEl = document.getElementById('modal-title');
        const bodyEl = document.getElementById('modal-body');
        
        titleEl.querySelector('#modal-severity-dot').className = `vuln-severity-dot ${v.severity.toLowerCase()}`;
        document.getElementById('modal-vuln-title').textContent = v.title;
        
        let html = `
            <div class="modal-meta">
                <div class="modal-meta-item">
                    <div class="modal-meta-label">Severity</div>
                    <div class="modal-meta-value ${v.severity.toLowerCase()}">${v.severity.toUpperCase()}</div>
                </div>
                <div class="modal-meta-item">
                    <div class="modal-meta-label">CVSS 3.1</div>
                    <div class="modal-meta-value ${v.severity.toLowerCase()}">${v.cvss ? v.cvss.toFixed(1) : 'N/A'}</div>
                </div>
                ${v.method ? `<div class="modal-meta-item"><div class="modal-meta-label">Method</div><div class="modal-meta-value">${esc(v.method)}</div></div>` : ''}
                ${v.cve ? `<div class="modal-meta-item"><div class="modal-meta-label">CVE</div><div class="modal-meta-value"><code class="modal-code">${esc(v.cve)}</code></div></div>` : ''}
            </div>
            ${v.cvss_vector ? `<div class="modal-section" style="margin-top:-8px;margin-bottom:8px"><code style="font-size:11px;color:var(--text-muted);background:var(--bg-primary);padding:4px 8px;border-radius:4px;display:inline-block">${esc(v.cvss_vector)}</code></div>` : ''}
        `;
        
        if (v.endpoint) html += `<div class="modal-section"><div class="modal-label">Endpoint</div><div class="modal-value"><code class="modal-code">${esc(v.endpoint)}</code></div></div>`;
        if (v.description) html += `<div class="modal-section"><div class="modal-label">Description</div><div class="modal-value">${mdToHtml(v.description)}</div></div>`;
        if (v.impact) html += `<div class="modal-section"><div class="modal-label">Impact</div><div class="modal-value">${mdToHtml(v.impact)}</div></div>`;
        if (v.technical_analysis) html += `<div class="modal-section"><div class="modal-label">Technical Analysis</div><div class="modal-value">${mdToHtml(v.technical_analysis)}</div></div>`;
        if (v.poc_description) html += `<div class="modal-section"><div class="modal-label">Proof of Concept</div><div class="modal-value">${mdToHtml(v.poc_description)}</div></div>`;
        if (v.poc_script) html += `<div class="modal-section"><div class="modal-label">PoC Script</div><pre class="modal-pre">${esc(v.poc_script)}</pre></div>`;
        if (v.remediation) html += `<div class="modal-section"><div class="modal-label">Remediation</div><div class="modal-value">${mdToHtml(v.remediation)}</div></div>`;
        
        bodyEl.innerHTML = html;
        modal.classList.add('active');
    };

    window.closeModal = function() {
        document.getElementById('vuln-modal').classList.remove('active');
    };

    // Close modal on click outside
    document.getElementById('vuln-modal').addEventListener('click', function(e) {
        if (e.target === this) closeModal();
    });

    // Close help modal on click outside
    document.getElementById('help-modal').addEventListener('click', function(e) {
        if (e.target === this) closeHelpModal();
    });

    // Close modal on ESC
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
            closeHelpModal();
        }
    });

    function updateToolStats() {
        const list = document.getElementById('tools-list');
        const countEl = document.getElementById('tools-count');
        const entries = Object.entries(toolUsage).sort((a, b) => b[1] - a[1]);
        
        // Calculate total tool calls
        const totalCalls = Object.values(toolUsage).reduce((sum, count) => sum + count, 0);
        
        // Update header stat to match
        const headerToolEl = document.getElementById('stat-tools');
        if (headerToolEl) headerToolEl.textContent = totalCalls;
        
        // Show total in sidebar count
        countEl.textContent = totalCalls;
        
        if (entries.length === 0) {
            list.innerHTML = '<li class="empty-state" style="padding: 20px 0"><div class="empty-title" style="font-size: 13px">No tools used yet</div></li>';
            return;
        }
        
        list.innerHTML = entries.map(([name, count]) => `
            <li style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-subtle)">
                <span style="font-size:12px;color:var(--text-secondary)">${TOOL_ICONS[name] || '🔧'} ${name.replace(/_/g, ' ')}</span>
                <span style="font-size:12px;font-weight:600;color:var(--accent-primary)">${count}</span>
            </li>
        `).join('');
    }

    // ── Queue UI ───────────────────────────────────────────
    function showQueueBar() {
        document.getElementById('queue-bar').classList.add('active');
    }

    function updateQueueBar(idx, total, target, subIdx, subTotal) {
        let progressText;
        if (subIdx && subTotal) {
            // Wildcard subdomain scanning: show "1.3/2" format
            progressText = `Scanning ${idx}.${subIdx}/${total} (${subIdx}/${subTotal} subdomains)`;
        } else {
            progressText = `Scanning ${idx}/${total}`;
        }
        document.getElementById('queue-progress').textContent = progressText;
        document.getElementById('queue-target').textContent = target || '';
        // Calculate fill percentage
        let fillPercent;
        if (subIdx && subTotal) {
            // Sub-progress within current main target
            const mainProgress = (idx - 1) / total;
            const subProgress = subIdx / subTotal / total;
            fillPercent = (mainProgress + subProgress) * 100;
        } else {
            fillPercent = (idx / total) * 100;
        }
        document.getElementById('queue-fill').style.width = `${fillPercent}%`;
    }

    function hideQueueBar() {
        document.getElementById('queue-bar').classList.remove('active');
    }

    // ── DOM Helpers ────────────────────────────────────────
    function addFeedItem(el, replace) {
        const feed = document.getElementById('feed-body');
        if (replace) {
            const lastThink = feed.querySelector('.event-think:last-of-type');
            if (lastThink) lastThink.remove();
        }
        feed.appendChild(el);
        // Smart auto-scroll: only scroll if enabled
        if (autoScroll) {
            feed.scrollTop = feed.scrollHeight;
        }
    }

    function hideEmptyState() {
        const empty = document.getElementById('empty-state');
        if (empty) empty.style.display = 'none';
    }

    function setStatus(cls, text) {
        const badge = document.getElementById('status-badge');
        badge.className = `status-badge ${cls}`;
        document.getElementById('status-text').textContent = text;
        
        const feedCard = document.getElementById('feed-card');
        feedCard.classList.toggle('scanning', cls === 'running');
    }

    function toggleButtons(running) {
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');
        startBtn.classList.toggle('hidden', running);
        stopBtn.classList.toggle('hidden', !running);
        startBtn.disabled = false;
    }

    function showReportButton(url) {
        // Remove existing
        const existing = document.querySelector('.report-btn');
        if (existing) existing.remove();
        
        // Add to first sidebar card
        const card = document.querySelector('.sidebar-card');
        const btn = document.createElement('a');
        btn.href = url;
        btn.target = '_blank';
        btn.className = 'report-btn';
        btn.innerHTML = '📄 Download PDF Report';
        card.parentNode.insertBefore(btn, card.nextSibling);
    }

    function hasToolTags(str) {
        return /<function=|<\/function>|<parameter[= ]|<\/parameter>|<invoke\s/.test(str);
    }

    function esc(str) {
        const d = document.createElement('div');
        d.textContent = str || '';
        return d.innerHTML;
    }

    // ── Timer ──────────────────────────────────────────────
    function formatDuration(totalSeconds) {
        const h = Math.floor(totalSeconds / 3600);
        const m = Math.floor((totalSeconds % 3600) / 60);
        const s = totalSeconds % 60;
        // Fixed format: HH:MM:SS
        return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    }

    function startTimer(startFrom) {
        scanStart = startFrom ? new Date(startFrom).getTime() : Date.now();
        // Show chat input when scan starts
        document.getElementById('chat-input-container').style.display = 'block';
    }

    function hideChatInput() {
        document.getElementById('chat-input-container').style.display = 'none';
    }

    // ── Chat Functions ─────────────────────────────────────
    window.sendChatMessage = async function() {
        const input = document.getElementById('chat-input');
        const btn = document.getElementById('chat-send-btn');
        const message = input.value.trim();
        if (!message) return;

        input.value = '';
        if (btn) { btn.disabled = true; btn.textContent = '...'; }

        // Add user message to feed
        const feedBody = document.getElementById('feed-body');
        const userMsg = document.createElement('div');
        userMsg.className = 'event event-message';
        userMsg.style.background = 'rgba(30, 41, 59, 0.5)';
        userMsg.style.padding = '10px';
        userMsg.style.margin = '5px 0';
        userMsg.style.borderRadius = '8px';
        userMsg.style.borderLeft = '3px solid #2DD4BF';
        userMsg.innerHTML = '<strong style="color: #2DD4BF">You:</strong> ' + esc(message);
        feedBody.appendChild(userMsg);
        scrollToBottom();

        // Send to server
        try {
            const resp = await fetch('/api/chat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message})
            });
            const data = await resp.json();

            // Add Xalgorix response to feed
            const botMsg = document.createElement('div');
            botMsg.className = 'event event-message';
            botMsg.style.padding = '10px';
            botMsg.style.margin = '5px 0';
            botMsg.style.borderLeft = '3px solid #F43F5E';
            botMsg.innerHTML = '<strong style="color: #F43F5E">Xalgorix:</strong> ' + mdToHtml(data.response);
            feedBody.appendChild(botMsg);
            scrollToBottom();
        } catch (e) {
            console.error('Chat error:', e);
            showToast('Chat error: ' + e.message, 'error');
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = '➤'; }
        }
    }

    // ── Stat Pop Animation ─────────────────────────────────
    function popStat(id) {
        const el = document.getElementById(id);
        el.classList.remove('pop');
        void el.offsetWidth;
        el.classList.add('pop');
    }

    // ── Live Clock ─────────────────────────────────────────
    function updateClock() {
        const now = new Date();
        
        // If scan is running, show scan duration
        if (scanRunning && scanStart) {
            const elapsed = Math.floor((Date.now() - scanStart) / 1000);
            const h = Math.floor(elapsed / 3600);
            const m = Math.floor((elapsed % 3600) / 60);
            const s = elapsed % 60;
            
            // Always show HH:MM:SS format
            const timeStr = `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
            document.getElementById('live-clock').textContent = timeStr;
        } else {
            // Show time of day when idle
            const h = String(now.getHours()).padStart(2, '0');
            const m = String(now.getMinutes()).padStart(2, '0');
            const s = String(now.getSeconds()).padStart(2, '0');
            document.getElementById('live-clock').textContent = `${h}:${m}:${s}`;
        }
    }
    setInterval(updateClock, 1000);
    updateClock();

    // ── File Upload: Targets ───────────────────────────────
    window.handleTargetsFile = function (input) {
        const file = input.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        fetch('/api/upload-targets', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.targets && data.targets.length > 0) {
                    document.getElementById('target-input').value = data.targets.join(', ');
                    loadedTargets = data.targets;
                    input.closest('.file-btn').classList.add('loaded');
                }
            })
            .catch(err => console.error('Upload error:', err))
            .finally(() => { input.value = ''; });
    };

    // ── File Upload: Instructions ──────────────────────────
    window.handleInstructionsFile = function (input) {
        const file = input.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        fetch('/api/upload-instructions', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.content) {
                    document.getElementById('instruction-input').value = data.content;
                    input.closest('.file-btn').classList.add('loaded');
                }
            })
            .catch(err => console.error('Upload error:', err))
            .finally(() => { input.value = ''; });
    };

    // ── Actions ────────────────────────────────────────────
    window.startScan = function () {
        const targetVal = document.getElementById('target-input').value.trim();
        if (!targetVal) {
            const targetEl = document.getElementById('target-input');
            targetEl.focus();
            targetEl.style.borderColor = '#F43F5E';
            setTimeout(() => targetEl.style.borderColor = '', 2000);
            return;
        }

        const instruction = document.getElementById('instruction-input').value.trim();
        const scanMode = document.getElementById('scan-mode').value;
        
        // Get severity filter
        const severityFilter = [];
        if (document.getElementById('sev-critical').checked) severityFilter.push('critical');
        if (document.getElementById('sev-high').checked) severityFilter.push('high');
        if (document.getElementById('sev-medium').checked) severityFilter.push('medium');
        if (document.getElementById('sev-low').checked) severityFilter.push('low');
        if (document.getElementById('sev-info').checked) severityFilter.push('info');
        
        // Parse targets from the input box directly to ensure values are always split properly.
        // This handles both manual input and file uploads correctly.
        const targets = targetVal.split(/[, \n\r\t]+/).map(t => t.trim()).filter(Boolean);

        // Reset state
        iterCount = 0; toolCount = 0; vulnCount = 0; eventCount = 0;
        currentTargetIdx = 0; totalTargets = targets.length;
        Object.keys(toolUsage).forEach(k => delete toolUsage[k]);
        
        ['stat-iter', 'stat-tools', 'stat-vulns'].forEach(id => {
            document.getElementById(id).textContent = '0';
        });
        
        document.getElementById('feed-body').innerHTML = '';
        document.getElementById('vuln-list').innerHTML = '<li class="empty-state" style="padding:20px 0"><div class="empty-title">Scanning...</div></li>';
        document.getElementById('tools-list').innerHTML = '<li class="empty-state" style="padding:20px 0"><div class="empty-title">Waiting...</div></li>';
        
        // Remove report button if exists
        const reportBtn = document.querySelector('.report-btn');
        if (reportBtn) reportBtn.remove();
        
        // Clear uploaded targets after sending
        loadedTargets = [];

        scanRunning = true;
        toggleButtons(true);
        setStatus('running', 'SCANNING');
        startTimer();

        const payload = { targets, instruction, scan_mode: scanMode, severity_filter: severityFilter };

        // Include LLM provider settings
        const provider = document.getElementById('llm-provider').value;
        const modelInput = document.getElementById('llm-model').value.trim();
        const apiKey = document.getElementById('llm-apikey').value.trim();
        const apiBase = document.getElementById('llm-apibase').value.trim();

        const p = LLM_PROVIDERS[provider] || {};
        // Only send LLM overrides if the user explicitly provided an API key in the UI.
        // The model/apibase fields are auto-populated by provider dropdown selection,
        // so they alone don't indicate user intent. The backend .xalgorix.env is used otherwise.
        if (apiKey) {
            const effectiveModel = modelInput || p.model || '';
            if (effectiveModel) {
                payload.model = p.prefix ? `${p.prefix}/${effectiveModel}` : effectiveModel;
            }
            if (!apiBase && p.base) {
                payload.api_base = p.base;
            }
            payload.api_key = apiKey;
        }
        if (apiBase) payload.api_base = apiBase;

        const discordWebhook = document.getElementById('discord-webhook')?.value?.trim();
        if (discordWebhook) payload.discord_webhook = discordWebhook;

        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(payload));
        } else {
            fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
        }
    };

    window.stopScan = function () {
        fetch('/api/stop', { method: 'POST' });
    };

    window.clearFeed = function() {
        // Reset timer state
        scanStart = null;
        scanRunning = false;
        document.getElementById('live-clock').textContent = '--:--:--';
        
        document.getElementById('feed-body').innerHTML = `
            <div class="empty-state" id="empty-state">
                <div class="empty-icon">🎯</div>
                <div class="empty-title">Ready to Scan</div>
                <div class="empty-desc">Enter a target and start your pentest</div>
            </div>
        `;
    };

    window.downloadEvents = function() {
        const feed = document.getElementById('feed-body');
        const text = feed.innerText;
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'xalgorix-feed.txt';
        a.click();
        // Prevent memory leak
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    };

    window.scrollToBottom = function() {
        const feed = document.getElementById('feed-body');
        feed.scrollTop = feed.scrollHeight;
    };

    // Auto-scroll toggle
    window.toggleAutoScroll = function() {
        autoScroll = !autoScroll;
        const btn = document.getElementById('scroll-toggle');
        btn.classList.toggle('active', autoScroll);
        if (autoScroll) scrollToBottom();
    };

    window.loadLastScan = async function() {
        // First check if there's a running scan via /api/status
        try {
            const statusResp = await fetch('/api/status');
            const status = await statusResp.json();
            
            if (status.running && status.scan_id) {
                // There's a running scan, load it
                history.replaceState(null, '', '/' + status.scan_id);
                await loadScanById(status.scan_id);
                // Show chat input when scan is running
                document.getElementById('chat-input-container').style.display = 'block';
                return;
            }
        } catch (e) {
            console.log('Status check failed');
        }
        
        // Otherwise try to load from URL path
        let scanId = window.location.pathname.replace('/', '');
        if (!scanId) {
            // Try to get latest scan
            try {
                const resp = await fetch('/api/scans/latest');
                const latest = await resp.json();
                if (latest && latest.id) {
                    scanId = latest.id;
                    history.replaceState(null, '', '/' + scanId);
                }
            } catch (e) {
                console.log('No latest scan found');
                return;
            }
        }
        
        if (scanId) {
            await loadScanById(scanId);
        }
    };

    async function loadScanById(scanId) {
        try {
            const resp = await fetch(`/api/scans/${encodeURIComponent(scanId)}`);
            const scan = await resp.json();
            if (!scan || !scan.id) return;

            // Reset UI
            iterCount = scan.iterations || 0;
            toolCount = scan.tool_calls || 0;
            vulnCount = (scan.vulns || []).length;
            
            const iterEl = document.getElementById('stat-iter');
            const toolsEl = document.getElementById('stat-tools');
            const vulnsEl = document.getElementById('stat-vulns');
            const tokensEl = document.getElementById('stat-tokens');
            
            if (iterEl) iterEl.textContent = String(iterCount);
            if (toolsEl) toolsEl.textContent = String(toolCount);
            if (vulnsEl) vulnsEl.textContent = String(vulnCount);

            // Tokens
            if (scan.total_tokens > 0 && tokensEl) {
                const formatted = scan.total_tokens >= 1000000
                    ? (scan.total_tokens / 1000000).toFixed(1) + 'M'
                    : scan.total_tokens >= 1000
                    ? (scan.total_tokens / 1000).toFixed(1) + 'K'
                    : String(scan.total_tokens);
                tokensEl.textContent = formatted;
            }

            // Vulns
            if (scan.vulns && scan.vulns.length > 0) {
                renderVulns(scan.vulns);
            }

            // Events
            const feed = document.getElementById('feed-body');
            feed.innerHTML = '';
            const events = scan.events || [];
            
            if (events.length > 0) {
                events.slice(-100).forEach(evt => {
                    const div = document.createElement('div');
                    if (evt.type === 'thinking') {
                        div.className = 'event event-think';
                        div.innerHTML = `<div class="typing"><span></span><span></span><span></span></div> ${esc(evt.content || '')}`;
                    } else if (evt.type === 'tool_call') {
                        div.className = 'event event-tool';
                        div.innerHTML = `<div class="event-tool-header"><span class="event-tool-icon">${TOOL_ICONS[evt.tool_name] || '🔧'}</span><span class="event-tool-name">${esc(evt.tool_name)}</span></div>`;
                    } else if (evt.type === 'tool_result') {
                        div.className = 'event event-result';
                        div.textContent = (evt.output || '').slice(0, 200);
                    } else if (evt.type === 'message') {
                        div.className = 'event event-message';
                        div.textContent = evt.content;
                    } else if (evt.type === 'finished') {
                        div.className = 'event event-finished';
                        div.textContent = `✅ ${evt.content || 'Completed'}`;
                    }
                    if (div.innerHTML) feed.appendChild(div);
                });
            }

            // Tool usage
            (scan.events || []).filter(e => e.type === 'tool_call').forEach(e => {
                toolUsage[e.tool_name] = (toolUsage[e.tool_name] || 0) + 1;
            });
            updateToolStats();

            // Status
            try {
                const statusResp = await fetch('/api/status');
                const serverStatus = await statusResp.json();
                if (serverStatus.running) {
                    setStatus('running', 'SCANNING');
                    scanRunning = true;
                    toggleButtons(true);
                    startTimer(scan.started_at ? new Date(scan.started_at) : null);
                } else if (scan.status === 'finished') {
                    setStatus('finished', 'COMPLETED');
                    showReportButton(`/api/report/${encodeURIComponent(scan.id)}`);
                }
            } catch (e) {}

            if (scan.target) {
                document.getElementById('target-input').value = scan.target;
            }

            feed.scrollTop = feed.scrollHeight;
        } catch (e) {
            console.log('No previous scan to restore');
        }
    };

    window.showHelp = function() {
        const modal = document.getElementById('help-modal');
        modal.classList.add('active');
    };

    window.closeHelpModal = function() {
        document.getElementById('help-modal').classList.remove('active');
    };

    // Enter key to start scan (but NOT when focused on chat input or other text inputs)
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && !scanRunning 
            && document.activeElement.tagName !== 'TEXTAREA'
            && document.activeElement.id !== 'chat-input'
            && !document.activeElement.closest('.settings-toggle')) {
            window.startScan();
        }
    });

    // LLM Provider Change
    window.onProviderChange = function () {
        const provider = document.getElementById('llm-provider').value;
        const p = LLM_PROVIDERS[provider] || {};
        document.getElementById('llm-model').value = p.model || '';
        document.getElementById('llm-apibase').value = p.base || '';
        document.getElementById('llm-model').placeholder = p.model ? `e.g. ${p.model}` : 'Model name';
    };

    // Rate Limiting
    window.saveRateLimit = async function() {
        const requests = parseInt(document.getElementById('rate-limit-requests').value) || 60;
        const windowSec = parseInt(document.getElementById('rate-limit-window').value) || 60;
        
        try {
            const resp = await fetch('/api/settings/rate-limit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ requests, window: windowSec })
            });
            const data = await resp.json();
            
            const statusEl = document.getElementById('rate-limit-status');
            statusEl.textContent = `✅ Saved: ${data.requests} requests/${data.window}s`;
            statusEl.style.color = 'var(--success)';
            
            // Hide status after 3 seconds
            setTimeout(() => {
                statusEl.textContent = '';
            }, 3000);
        } catch (err) {
            const statusEl = document.getElementById('rate-limit-status');
            statusEl.textContent = '❌ Failed to save';
            statusEl.style.color = 'var(--danger)';
        }
    };

    // AgentMail Settings
    window.saveAgentMail = async function() {
        const pod = document.getElementById('agentmail-pod').value.trim();
        const apiKey = document.getElementById('agentmail-apikey').value.trim();
        
        if (!pod || !apiKey) {
            const statusEl = document.getElementById('agentmail-status');
            statusEl.textContent = '❌ Please fill in both Pod and API Key';
            statusEl.style.color = 'var(--danger)';
            setTimeout(() => statusEl.textContent = '', 3000);
            return;
        }
        
        try {
            const resp = await fetch('/api/settings/agentmail', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pod, apiKey })
            });
            const data = await resp.json();
            
            const statusEl = document.getElementById('agentmail-status');
            statusEl.textContent = '✅ Saved AgentMail settings';
            statusEl.style.color = 'var(--success)';
            setTimeout(() => statusEl.textContent = '', 3000);
        } catch (err) {
            console.error('Failed to save AgentMail settings:', err);
            const statusEl = document.getElementById('agentmail-status');
            statusEl.textContent = '❌ Failed to save';
            statusEl.style.color = 'var(--danger)';
        }
    };

    async function loadRateLimitSettings() {
        try {
            const resp = await fetch('/api/settings/rate-limit');
            const data = await resp.json();
            document.getElementById('rate-limit-requests').value = data.requests;
            document.getElementById('rate-limit-window').value = data.window;
        } catch (err) {
            console.log('Could not load rate limit settings');
        }
    }

    // Initialize severity checkbox handlers
    function initSeverityCheckboxes() {
        const checkboxes = ['sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info'];
        checkboxes.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                const label = el.closest('.severity-checkbox');
                if (el.checked) {
                    label.classList.add('checked');
                }
                el.addEventListener('change', function() {
                    if (this.checked) {
                        label.classList.add('checked');
                    } else {
                        label.classList.remove('checked');
                    }
                });
            }
        });
    }

    // Initialize
    window.onProviderChange();
    loadRateLimitSettings();

    // Load AgentMail settings
    async function loadAgentMailSettings() {
        try {
            const resp = await fetch('/api/settings/agentmail');
            const data = await resp.json();
            if (data.pod) {
                document.getElementById('agentmail-pod').value = data.pod;
            }
            if (data.apiKey) {
                document.getElementById('agentmail-apikey').value = data.apiKey;
                document.getElementById('agentmail-apikey').placeholder = '••••••••';
            }
        } catch (err) {
            console.log('Could not load AgentMail settings');
        }
    }
    loadAgentMailSettings();
    initSeverityCheckboxes();

    // ── Toast Notification System ──────────────────────────
    function showToast(message, type = 'info', duration = 3500) {
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
    // Make available globally
    window.showToast = showToast;

    connect();
    
    // Polling fallback - check status every 5 seconds in case WebSocket fails
    setInterval(async () => {
        try {
            const resp = await fetch('/api/status');
            const status = await resp.json();
            if (status.running && !scanRunning) {
                // Scan started while we were disconnected - load it gracefully
                scanRunning = true;
                toggleButtons(true);
                setStatus('running', 'SCANNING');
                startTimer();
                await loadLastScan();
            } else if (!status.running && scanRunning) {
                // Scan finished while we were disconnected - update UI gracefully
                // Do NOT reload the page — that wipes the live feed!
                scanRunning = false;
                setStatus('finished', 'COMPLETED');
                toggleButtons(false);
                hideQueueBar();
                hideChatInput();
                // Add a completion banner if one doesn't already exist
                const feed = document.getElementById('feed-body');
                const hasFinished = feed.querySelector('.event-finished');
                if (!hasFinished) {
                    addFeedItem(renderBanner('🏁', 'Scan completed (recovered from connection loss)', 'success'));
                    showToast('🏁 Scan completed', 'success');
                }
            }
        } catch (e) {}
    }, 5000);
    
    // Fetch and display version
    async function loadVersion() {
        try {
            const resp = await fetch('/api/version');
            const data = await resp.json();
            if (data.version) {
                document.getElementById('version-display').textContent = data.version;
            }
        } catch (e) {
            console.error('Failed to load version:', e);
        }
    }
    loadVersion();
    
    // Check server status
    async function checkServerStatus() {
        try {
            const resp = await fetch('/api/status');
            const status = await resp.json();
            
            // Check URL path for routing
            const path = window.location.pathname;
            
            if (path && path !== '/' && path.length > 1) {
                // Direct link to a scan — check if it's an instance
                const instanceId = path.slice(1);
                try {
                    const instResp = await fetch('/api/instances/' + instanceId);
                    if (instResp.ok) {
                        navigateToInstance(instanceId);
                        return;
                    }
                } catch (e) {}
                
                // Legacy: treat as scan ID
                showScanView();
                if (status.running && status.scan_id) {
                    scanRunning = true;
                    toggleButtons(true);
                    setStatus('running', 'SCANNING');
                }
                await loadLastScan();
            } else {
                // Root path — show dashboard
                showDashboardView();
            }
        } catch (e) {
            showDashboardView();
        }
    }

    // ── DASHBOARD / SPA ROUTING ────────────────────────────────────────
    
    function showDashboardView() {
        currentView = 'dashboard';
        currentInstanceID = null;
        document.getElementById('dashboard-view').classList.remove('hidden');
        document.getElementById('scan-view').classList.add('hidden');
        history.replaceState(null, '', '/');
        
        // Unsubscribe from instance events
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ unsubscribe: true }));
        }
        
        refreshInstances();
        startInstancePolling();
    }
    
    function showScanView() {
        currentView = 'scan';
        document.getElementById('dashboard-view').classList.add('hidden');
        document.getElementById('scan-view').classList.remove('hidden');
        stopInstancePolling();
    }
    
    function navigateToInstance(instanceId) {
        currentInstanceID = instanceId;
        showScanView();
        history.pushState(null, '', '/' + instanceId);
        document.getElementById('scan-view-instance-id').textContent = 'Instance: ' + instanceId;
        
        // Subscribe to this instance's events
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ subscribe: instanceId }));
        }
        
        // Reset scan view state
        iterCount = 0; toolCount = 0; vulnCount = 0; eventCount = 0;
        Object.keys(toolUsage).forEach(k => delete toolUsage[k]);
        ['stat-iter', 'stat-tools', 'stat-vulns'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '0';
        });
        document.getElementById('feed-body').innerHTML = '';
        document.getElementById('vuln-list').innerHTML = '<li class="empty-state" style="padding:20px 0"><div class="empty-title">Loading...</div></li>';
        document.getElementById('tools-list').innerHTML = '<li class="empty-state" style="padding:20px 0"><div class="empty-title">Loading...</div></li>';
        
        // Load instance state
        loadInstanceState(instanceId);
    }
    
    async function loadInstanceState(instanceId) {
        try {
            const resp = await fetch('/api/instances/' + instanceId);
            if (!resp.ok) return;
            const inst = await resp.json();
            
            // Populate target input
            if (inst.targets) {
                const targetInput = document.getElementById('target-input');
                if (targetInput) targetInput.value = inst.targets;
            }
            
            if (inst.status === 'running') {
                scanRunning = true;
                toggleButtons(true);
                setStatus('running', 'SCANNING');
                startTimer();
            } else {
                scanRunning = false;
                toggleButtons(false);
                setStatus(inst.status === 'stopped' ? 'finished' : 'finished', inst.status.toUpperCase());
            }
            
            // Update stats — use Math.max to avoid resetting counters
            // that WS events may have already incremented
            if (inst.iterations) {
                iterCount = Math.max(iterCount, inst.iterations);
                const el = document.getElementById('stat-iter');
                if (el) el.textContent = iterCount;
            }
            if (inst.tool_calls) {
                toolCount = Math.max(toolCount, inst.tool_calls);
                const el = document.getElementById('stat-tools');
                if (el) el.textContent = toolCount;
            }
            if (inst.vuln_count) {
                vulnCount = Math.max(vulnCount, inst.vuln_count);
                const el = document.getElementById('stat-vulns');
                if (el) el.textContent = vulnCount;
            }
            if (inst.total_tokens) {
                const el = document.getElementById('stat-tokens');
                if (el) el.textContent = inst.total_tokens > 999 ? Math.round(inst.total_tokens / 1000) + 'K' : inst.total_tokens;
            }
            
            // Load buffered vulns
            if (inst.vulns && inst.vulns.length > 0) {
                const vulnList = document.getElementById('vuln-list');
                vulnList.innerHTML = '';
                inst.vulns.forEach(v => {
                    const li = document.createElement('li');
                    li.className = 'vuln-item';
                    li.innerHTML = `
                        <span class="vuln-severity-dot ${(v.severity||'info').toLowerCase()}"></span>
                        <span class="vuln-title">${esc(v.title)}</span>
                        <span class="vuln-cvss">${v.cvss || ''}</span>
                    `;
                    vulnList.appendChild(li);
                });
            }
            
            // Load buffered events (replay feed)
            try {
                const evResp = await fetch('/api/instances/' + instanceId + '/events');
                if (evResp.ok) {
                    const events = await evResp.json();
                    if (events && events.length > 0) {
                        hideEmptyState();
                        events.forEach(evt => handleEvent(evt, true)); // true = replay mode (no sound/toast)
                    }
                }
            } catch (e) {
                console.warn('Failed to load event history:', e);
            }
        } catch (e) {
            console.error('Failed to load instance state:', e);
        }
    }
    
    window.navigateToDashboard = function() {
        showDashboardView();
    };
    
    window.showNewScanPanel = function() {
        document.getElementById('new-scan-panel').classList.remove('hidden');
        document.getElementById('dash-target-input').focus();
    };
    
    window.hideNewScanPanel = function() {
        document.getElementById('new-scan-panel').classList.add('hidden');
    };
    
    window.startDashboardScan = function() {
        const target = document.getElementById('dash-target-input').value.trim();
        if (!target) {
            document.getElementById('dash-target-input').style.borderColor = '#ff3366';
            setTimeout(() => document.getElementById('dash-target-input').style.borderColor = '', 2000);
            return;
        }
        const mode = document.getElementById('dash-scan-mode').value;
        
        // Collect severity filter
        const severities = [];
        ['critical', 'high', 'medium', 'low', 'info'].forEach(s => {
            const cb = document.getElementById('dash-sev-' + s);
            if (cb && cb.checked) severities.push(s);
        });
        
        // Collect instruction
        const instruction = (document.getElementById('dash-instruction-input') || {}).value || '';
        
        // Collect LLM settings
        const payload = {
            targets: [target],
            scan_mode: mode,
            instruction: instruction,
            severity_filter: severities,
        };
        
        const model = (document.getElementById('dash-llm-model') || {}).value;
        const apiKey = (document.getElementById('dash-llm-apikey') || {}).value;
        const apiBase = (document.getElementById('dash-llm-apibase') || {}).value;
        const discord = (document.getElementById('dash-discord-webhook') || {}).value;
        
        if (model) payload.model = model;
        if (apiKey) payload.api_key = apiKey;
        if (apiBase) payload.api_base = apiBase;
        if (discord) payload.discord_webhook = discord;
        
        fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        }).then(r => r.json()).then(data => {
            if (data.instance_id) {
                hideNewScanPanel();
                document.getElementById('dash-target-input').value = '';
                if (document.getElementById('dash-instruction-input')) document.getElementById('dash-instruction-input').value = '';
                showToast('🚀 Scan started: ' + target, 'success');
                setTimeout(() => refreshInstances(), 500);
            }
        }).catch(e => showToast('Failed to start scan', 'error'));
    };
    
    // Dashboard file upload handlers
    window.handleDashTargetsFile = function(input) {
        const file = input.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = function(e) {
            const lines = e.target.result.split('\n').map(l => l.trim()).filter(l => l);
            document.getElementById('dash-target-input').value = lines.join(', ');
            showToast('📂 Loaded ' + lines.length + ' targets from ' + file.name, 'success');
            input.value = '';
        };
        reader.readAsText(file);
    };
    
    window.handleDashInstructionsFile = function(input) {
        const file = input.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('dash-instruction-input').value = e.target.result;
            showToast('📄 Loaded instructions from ' + file.name, 'success');
            input.value = '';
        };
        reader.readAsText(file);
    };
    
    // Instance polling
    function startInstancePolling() {
        stopInstancePolling();
        refreshInstances();
        instancePollTimer = setInterval(refreshInstances, 3000);
    }
    
    function stopInstancePolling() {
        if (instancePollTimer) {
            clearInterval(instancePollTimer);
            instancePollTimer = null;
        }
    }
    
    async function refreshInstances() {
        try {
            const resp = await fetch('/api/instances');
            const instances = await resp.json();
            renderInstanceGrid(instances || []);
        } catch (e) {
            console.error('Failed to fetch instances:', e);
        }
    }
    
    function renderInstanceGrid(instances) {
        const grid = document.getElementById('instance-grid');
        const empty = document.getElementById('dashboard-empty');
        
        if (instances.length === 0) {
            grid.innerHTML = '';
            grid.appendChild(empty || createEmptyState());
            return;
        }
        
        if (empty) empty.remove();
        
        // Build cards
        const html = instances.map(inst => {
            const modeIcons = { single: '🎯', dast: '🔍', wildcard: '🌐' };
            const modeIcon = modeIcons[inst.scan_mode] || '🎯';
            const elapsed = inst.started_at ? getElapsed(inst.started_at) : '—';
            
            return `
            <div class="instance-card ${inst.status}" onclick="navigateToInstance('${inst.id}')" title="Click to view">
                <div class="instance-card-header">
                    <span class="instance-card-target" title="${escapeHtml(inst.targets)}">${escapeHtml(inst.targets)}</span>
                    <span class="instance-card-status ${inst.status}">
                        <span class="status-dot"></span>
                        ${inst.status}
                    </span>
                </div>
                <div class="instance-card-stats">
                    <div class="instance-card-stat">
                        <div class="instance-card-stat-value">${inst.iterations || 0}</div>
                        <div class="instance-card-stat-label">Iterations</div>
                    </div>
                    <div class="instance-card-stat">
                        <div class="instance-card-stat-value">${inst.tool_calls || 0}</div>
                        <div class="instance-card-stat-label">Tools</div>
                    </div>
                    <div class="instance-card-stat">
                        <div class="instance-card-stat-value">${inst.vuln_count || 0}</div>
                        <div class="instance-card-stat-label">Vulns</div>
                    </div>
                    <div class="instance-card-stat">
                        <div class="instance-card-stat-value">${formatTokens(inst.total_tokens || 0)}</div>
                        <div class="instance-card-stat-label">Tokens</div>
                    </div>
                </div>
                <div class="instance-card-meta">
                    <span class="instance-card-mode">${modeIcon} ${(inst.scan_mode || 'single').toUpperCase()}</span>
                    <span class="instance-card-time">${elapsed}</span>
                </div>
                ${inst.status === 'running' || inst.status === 'pending' ? `
                <div class="instance-card-actions">
                    <button class="btn btn-danger" onclick="event.stopPropagation(); stopInstance('${inst.id}')" style="font-size:11px;padding:4px 12px;">■ Cancel</button>
                </div>` : ''}
            </div>`;
        }).join('');
        
        grid.innerHTML = html;
    }
    
    function createEmptyState() {
        const div = document.createElement('div');
        div.className = 'empty-state';
        div.id = 'dashboard-empty';
        div.innerHTML = '<div class="empty-icon">🛡️</div><div class="empty-title">No Active Scans</div><div class="empty-desc">Click "New Scan" to start your first pentesting session</div>';
        return div;
    }
    
    function escapeHtml(text) {
        if (!text) return '';
        return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    
    function getElapsed(startedAt) {
        try {
            const start = new Date(startedAt);
            const diff = Math.floor((Date.now() - start) / 1000);
            if (diff < 60) return diff + 's';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ' + (diff % 60) + 's';
            return Math.floor(diff / 3600) + 'h ' + Math.floor((diff % 3600) / 60) + 'm';
        } catch (e) { return '—'; }
    }
    
    function formatTokens(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(0) + 'K';
        return String(n);
    }
    
    window.navigateToInstance = function(instanceId) {
        navigateToInstance(instanceId);
    };
    
    window.stopInstance = async function(instanceId) {
        try {
            await fetch('/api/instances/' + instanceId + '/stop', { method: 'POST' });
            showToast('Stopping instance...', 'warning');
            setTimeout(refreshInstances, 500);
        } catch (e) {
            showToast('Failed to stop instance', 'error');
        }
    };
    
    // Handle browser back/forward
    window.addEventListener('popstate', () => {
        const path = window.location.pathname;
        if (path === '/' || path === '') {
            showDashboardView();
        } else {
            navigateToInstance(path.slice(1));
        }
    });
    
    checkServerStatus();
})();
