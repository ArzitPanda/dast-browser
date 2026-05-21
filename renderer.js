const { ipcRenderer } = require('electron');

// UI Elements
const urlInput = document.getElementById('url-input');
const btnGo = document.getElementById('btn-go');
const btnBack = document.getElementById('btn-back');
const btnForward = document.getElementById('btn-forward');
const btnReload = document.getElementById('btn-reload');

const chatInput = document.getElementById('chat-input');
const btnSend = document.getElementById('btn-send');
const chatLog = document.getElementById('chat-log');

const btnExtract = document.getElementById('btn-extract');
const llmModelInput = document.getElementById('llm-model');

// Attack Config UI
const modeToggle = document.getElementById('mode-toggle');
const modeText = document.getElementById('mode-text');
const manualControls = document.getElementById('manual-controls');
const autoControls = document.getElementById('auto-controls');
const btnTagInput = document.getElementById('btn-tag-input');
const btnTagSubmit = document.getElementById('btn-tag-submit');
const btnAutoDetect = document.getElementById('btn-auto-detect');
const lblTargetInput = document.getElementById('lbl-target-input');
const lblTargetSubmit = document.getElementById('lbl-target-submit');
const btnRunAttack = document.getElementById('btn-run-attack');

let lastContext = null;
let targetInputSelectors = [];
let targetSubmitSelector = null;

// Navigation
btnGo.addEventListener('click', async () => {
    let url = urlInput.value.trim();
    if (!url) return;
    try {
        const finalUrl = await ipcRenderer.invoke('navigate', url);
        urlInput.value = finalUrl;
    } catch (e) {
        console.error('Navigation failed', e);
    }
});

urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') btnGo.click();
});

btnBack.addEventListener('click', () => ipcRenderer.send('go-back'));
btnForward.addEventListener('click', () => ipcRenderer.send('go-forward'));
btnReload.addEventListener('click', () => ipcRenderer.send('reload'));

// Helper to add messages to chat
function appendMessage(role, text) {
    const div = document.createElement('div');
    div.className = `message ${role}-msg`;
    // Basic formatting for code blocks
    const formattedText = text.replace(/```([\s\S]*?)```/g, '<pre style="background:#0f172a;padding:8px;border-radius:4px;overflow-x:auto;margin-top:8px;"><code>$1</code></pre>');
    div.innerHTML = formattedText;
    chatLog.appendChild(div);
    chatLog.scrollTop = chatLog.scrollHeight;
}

// Extract Context
btnExtract.addEventListener('click', async () => {
    btnExtract.disabled = true;
    btnExtract.textContent = "Extracting...";
    try {
        const context = await ipcRenderer.invoke('extract-context');
        lastContext = context;

        let msg = `Extracted context from: ${context.url || 'Unknown'}\n`;
        if (context.forms && context.forms.length > 0) {
            msg += `Found ${context.forms.length} form(s).`;
        } else {
            msg += `No forms found on this page.`;
        }

        appendMessage('system', msg);
    } catch (err) {
        appendMessage('system', `Extraction failed: ${err.message}`);
    } finally {
        btnExtract.disabled = false;
        btnExtract.textContent = "Extract Page Context";
    }
});

// Chat with LLM
btnSend.addEventListener('click', async () => {
    const prompt = chatInput.value.trim();
    if (!prompt) return;

    appendMessage('user', prompt);
    chatInput.value = '';

    let fullPrompt = prompt;
    if (lastContext) {
        fullPrompt = `Given this web page context:\n${JSON.stringify(lastContext, null, 2)}\n\nUser Request: ${prompt}

If the user is asking you to test for vulnerabilities or perform an attack, you MUST act as an autonomous agent. Analyze the context to find all relevant target inputs and submit buttons. Output your attack plan in a JSON block formatted exactly like this:
\`\`\`json
{
  "action": "agentic_attack",
  "targets": [
    {
      "inputSelectors": ["<css selector 1>", "<css selector 2>"],
      "submitSelector": "<css selector for submit button>"
    }
  ],
  "payloads": ["payload1", "payload2", "payload3"]
}
\`\`\`
Provide any explanations outside of the JSON block.`;
    }

    const model = llmModelInput.value.trim() || 'llama3';

    appendMessage('system', '<i>LLM is thinking...</i>');
    const loadingNode = chatLog.lastChild;

    try {
        const response = await ipcRenderer.invoke('llm-chat', model, fullPrompt);
        chatLog.removeChild(loadingNode);
        appendMessage('llm', response);

        // Check for Agentic JSON Plan
        const jsonMatch = response.match(/```json\n([\s\S]*?)```/);
        if (jsonMatch && jsonMatch[1]) {
            try {
                const plan = JSON.parse(jsonMatch[1].trim());
                if (plan.action === 'agentic_attack' && plan.targets && plan.payloads) {
                    const execBtn = document.createElement('button');
                    execBtn.className = 'action-btn';
                    execBtn.style.marginTop = '8px';
                    execBtn.style.backgroundColor = 'var(--danger)';
                    execBtn.style.borderColor = 'var(--danger)';
                    execBtn.style.color = 'white';

                    let targetCount = plan.targets.reduce((acc, t) => acc + (t.inputSelectors ? t.inputSelectors.length : 0), 0);
                    execBtn.innerHTML = `<b>Approve & Run Attack Plan</b><br><span style="font-size:10px">${plan.payloads.length} payloads against ${targetCount} input(s)</span>`;

                    execBtn.onclick = () => {
                        const tagged = plan.payloads.map(p => ({ payload: p, type: 'custom' }));
                        showPayloadModal(
                            tagged,
                            { targets: plan.targets },
                            () => { }
                        );
                    };
                    chatLog.lastChild.appendChild(execBtn);
                }
            } catch (err) {
                console.error("Failed to parse agent JSON:", err);
            }
        } else {
            // Fallback for single JS script execution
            const jsMatch = response.match(/```(?:javascript|js)\n([\s\S]*?)```/);
            if (jsMatch && jsMatch[1]) {
                const payload = jsMatch[1].trim();
                const execBtn = document.createElement('button');
                execBtn.className = 'action-btn';
                execBtn.style.marginTop = '8px';
                execBtn.textContent = 'Run Extracted Script';
                execBtn.onclick = async () => {
                    execBtn.textContent = 'Executing...';
                    const res = await ipcRenderer.invoke('execute-payload', payload);
                    if (res.success) {
                        execBtn.textContent = 'Executed Successfully';
                    } else {
                        execBtn.textContent = 'Execution Failed';
                        appendMessage('system', 'Execution Error: ' + res.error);
                    }
                };
                chatLog.lastChild.appendChild(execBtn);
            }
        }

    } catch (err) {
        chatLog.removeChild(loadingNode);
        appendMessage('system', `LLM Error: ${err.message}`);
    }
});

chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        btnSend.click();
    }
});

// --- Attack Configuration Logic ---
function updateAttackButtonState() {
    if (targetInputSelectors.length > 0 && targetSubmitSelector) {
        btnRunAttack.disabled = false;
    } else {
        btnRunAttack.disabled = true;
    }
}

modeToggle.addEventListener('change', () => {
    if (modeToggle.checked) {
        modeText.textContent = "Auto";
        manualControls.style.display = "none";
        autoControls.style.display = "flex";
    } else {
        modeText.textContent = "Manual";
        manualControls.style.display = "flex";
        autoControls.style.display = "none";
    }
});

btnTagInput.addEventListener('click', async () => {
    btnTagInput.classList.add('tagging-active');
    btnTagInput.textContent = "Click an input...";
    try {
        const selector = await ipcRenderer.invoke('start-tagging', 'input');
        if (selector && !targetInputSelectors.includes(selector)) {
            targetInputSelectors.push(selector);
            lblTargetInput.textContent = targetInputSelectors.join(', ');
            updateAttackButtonState();
        }
    } catch (e) {
        console.error(e);
    } finally {
        btnTagInput.classList.remove('tagging-active');
        btnTagInput.textContent = "Tag Another Input Field";
    }
});

btnTagSubmit.addEventListener('click', async () => {
    btnTagSubmit.classList.add('tagging-active');
    btnTagSubmit.textContent = "Click a submit button...";
    try {
        const selector = await ipcRenderer.invoke('start-tagging', 'submit');
        if (selector) {
            targetSubmitSelector = selector;
            lblTargetSubmit.textContent = selector;
            updateAttackButtonState();
        }
    } catch (e) {
        console.error(e);
    } finally {
        btnTagSubmit.classList.remove('tagging-active');
        btnTagSubmit.textContent = "Tag Submit Button";
    }
});

btnAutoDetect.addEventListener('click', async () => {
    if (!lastContext) {
        appendMessage('system', 'No page context available yet.');
        return;
    }
    btnAutoDetect.textContent = "Scanning...";
    try {
        await runAIPageScan(lastContext.url || 'current page');
    } catch (e) {
        appendMessage('system', 'Error detecting: ' + e.message);
    } finally {
        btnAutoDetect.textContent = "Auto-Detect Form";
    }
});

btnRunAttack.addEventListener('click', async () => {
    if (targetInputSelectors.length === 0 || !targetSubmitSelector) return;

    btnRunAttack.disabled = true;
    btnRunAttack.textContent = "Selecting...";

    try {
        // Show review modal with payloads from payloads.json
        const rawPayloads = await ipcRenderer.invoke('load-payloads');
        const tagged = [
            ...(rawPayloads.xss || []).map(p => ({ payload: p, type: 'xss' })),
            ...(rawPayloads.sqli || []).map(p => ({ payload: p, type: 'sqli' }))
        ];

        showPayloadModal(
            tagged,
            { targets: [{ inputSelectors: targetInputSelectors, submitSelector: targetSubmitSelector }] },
            () => { btnRunAttack.disabled = false; btnRunAttack.textContent = 'Run Automated Attack'; }
        );
    } catch (e) {
        appendMessage('system', 'Error loading payloads: ' + e.message);
        btnRunAttack.disabled = false;
        btnRunAttack.textContent = 'Run Automated Attack';
    }
});

// --- NEW: Automated Page Analysis on Load ---
async function runAIPageScan(url) {
    appendMessage('system', `<i>AI is scanning targets on: ${url}...</i>`);
    const loadingNode = chatLog.lastChild;

    try {
        const context = await ipcRenderer.invoke('extract-context');
        lastContext = context;

        const prompt = `I just navigated to: ${url}. 
Given this page context (forms, inputs, and buttons):
${JSON.stringify(context, null, 2)}

Analyze the page and identify the primary inputs and submit button. Also identify the types of attacks that can be performed on this page (e.g. XSS, SQLi).
Output your response in a JSON block formatted exactly like this:
\`\`\`json
{
  "overview": "Brief overview of what this page is (e.g. login page) and what vulnerabilities to test.",
  "suggestedAttacks": ["XSS", "SQLi"],
  "inputs": [
    { "selector": "<css selector>", "type": "text" }
  ],
  "submit": "<css selector for submit button>"
}
\`\`\`
Provide any explanations outside of the JSON block.`;

        const model = llmModelInput.value.trim() || 'llama-3.1-8b-instant';
        const response = await ipcRenderer.invoke('llm-chat', model, prompt);

        chatLog.removeChild(loadingNode);

        const jsonMatch = response.match(/```json\n([\s\S]*?)```/);
        if (jsonMatch && jsonMatch[1]) {
            const data = JSON.parse(jsonMatch[1].trim());

            appendMessage('llm', `<b>AI Scan Complete:</b><br>${data.overview}`);

            if (data.inputs && data.inputs.length > 0 && data.submit) {
                targetInputSelectors = data.inputs.map(i => i.selector);
                targetSubmitSelector = data.submit;

                lblTargetInput.textContent = targetInputSelectors.join(', ');
                lblTargetSubmit.textContent = targetSubmitSelector;

                updateAttackButtonState();

                // Force UI to Auto mode
                if (!modeToggle.checked) {
                    modeToggle.checked = true;
                    modeToggle.dispatchEvent(new Event('change'));
                }

                appendMessage('system', 'Targets locked! Ready to run automated attack.');
                
                const btnContainer = document.createElement('div');
                btnContainer.style.marginTop = '8px';
                
                if (data.suggestedAttacks && Array.isArray(data.suggestedAttacks) && data.suggestedAttacks.length > 0) {
                    data.suggestedAttacks.forEach(attackType => {
                        const attackBtn = document.createElement('button');
                        attackBtn.className = 'action-btn';
                        attackBtn.style.marginRight = '8px';
                        attackBtn.style.marginBottom = '8px';
                        attackBtn.textContent = `Next Step: Run ${attackType} Attack`;
                        attackBtn.onclick = () => btnRunAttack.click();
                        btnContainer.appendChild(attackBtn);
                    });
                } else {
                    const attackBtn = document.createElement('button');
                    attackBtn.className = 'action-btn';
                    attackBtn.textContent = 'Next Step: Run Automated Attack';
                    attackBtn.onclick = () => btnRunAttack.click();
                    btnContainer.appendChild(attackBtn);
                }
                
                chatLog.lastChild.appendChild(btnContainer);
            } else {
                appendMessage('system', 'AI could not confidently identify inputs and a submit button. Please use Manual mode.');
            }
        } else {
            appendMessage('llm', `<b>Page Analysis (${url}):</b><br>` + response);
        }
    } catch (err) {
        if (chatLog.contains(loadingNode)) chatLog.removeChild(loadingNode);
        appendMessage('system', `Page Analysis Failed: ${err.message}`);
    }
}

ipcRenderer.on('page-loaded', (event, url) => {
    runAIPageScan(url);
});

// --- Network Tab Logic ---
const networkList = document.getElementById('network-list');
const btnClearNetwork = document.getElementById('btn-clear-network');

btnClearNetwork.addEventListener('click', () => {
    networkList.innerHTML = '';
});

const networkFilter = document.getElementById('network-filter');
if (networkFilter) {
    networkFilter.addEventListener('input', () => {
        const filterText = networkFilter.value.toLowerCase();
        const items = networkList.querySelectorAll('.network-item');
        items.forEach(item => {
            const urlText = item.querySelector('.net-url').textContent.toLowerCase();
            if (urlText.includes(filterText)) {
                item.style.display = '';
            } else {
                item.style.display = 'none';
            }
        });
    });
}

ipcRenderer.on('network-request', (event, req) => {
    const item = document.createElement('div');
    item.className = 'network-item';
    item.id = `net-req-${req.id}`;
    item.style.cursor = 'pointer';
    item.title = 'Click to view details';
    
    item.innerHTML = `
        <span class="net-method ${req.method.toLowerCase()}">${req.method}</span>
        <span class="net-status" id="net-status-${req.id}">...</span>
        <span class="net-url" title="${req.url}">${req.url}</span>
        <span class="net-type">${req.resourceType || 'other'}</span>
    `;

    item.addEventListener('click', () => {
        ipcRenderer.send('show-network-details', req.id);
    });

    // Apply filter immediately if one is active
    const filterText = networkFilter?.value.toLowerCase() || '';
    if (filterText && !req.url.toLowerCase().includes(filterText)) {
        item.style.display = 'none';
    }

    // Add to the top of the list so newest is visible
    networkList.prepend(item);
    
    // Keep list from growing infinitely
    if (networkList.children.length > 500) {
        networkList.removeChild(networkList.lastChild);
    }
});

ipcRenderer.on('network-completed', (event, data) => {
    const statusEl = document.getElementById(`net-status-${data.id}`);
    if (statusEl) {
        statusEl.textContent = data.statusCode;
        if (data.statusCode >= 200 && data.statusCode < 300) {
            statusEl.className = 'net-status success';
        } else if (data.statusCode >= 300 && data.statusCode < 400) {
            statusEl.className = 'net-status redirect';
        } else {
            statusEl.className = 'net-status error';
        }
    }
});

ipcRenderer.on('network-error', (event, data) => {
    const statusEl = document.getElementById(`net-status-${data.id}`);
    if (statusEl) {
        statusEl.textContent = 'ERR';
        statusEl.className = 'net-status error';
        statusEl.title = data.error;
    }
});

// --- Tabs and Reports Logic ---
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const btnRefreshReports = document.getElementById('btn-refresh-reports');
const reportsList = document.getElementById('reports-list');

tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        // Remove active class from all
        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));

        // Add active class to clicked tab
        btn.classList.add('active');
        const targetId = btn.getAttribute('data-target');
        document.getElementById(targetId).classList.add('active');

        if (targetId === 'tab-reports') {
            loadReports();
        }
    });
});

btnRefreshReports.addEventListener('click', loadReports);

async function loadReports() {
    try {
        const reports = await ipcRenderer.invoke('list-reports');
        reportsList.innerHTML = '';

        if (reports.length === 0) {
            reportsList.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">No reports generated yet.</div>';
            return;
        }

        reports.forEach(report => {
            const item = document.createElement('div');
            item.className = 'report-item';

            const date = new Date(report.mtime).toLocaleString();

            item.innerHTML = `
                <div class="report-info">
                    <span class="report-title">${report.name}</span>
                    <span class="report-date">${date}</span>
                </div>
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            `;

            item.addEventListener('click', () => {
                ipcRenderer.send('open-report', report.path);
            });

            reportsList.appendChild(item);
        });
    } catch (e) {
        console.error("Failed to load reports", e);
        reportsList.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--danger);">Failed to load reports.</div>';
    }
}

// Auto-refresh & switch to Reports tab when a new report is saved
ipcRenderer.on('report-generated', () => {
    tabBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));
    document.querySelector('[data-target="tab-reports"]').classList.add('active');
    document.getElementById('tab-reports').classList.add('active');
    loadReports();
});

// --- Payload Review Modal ---
const payloadModal = document.getElementById('payload-modal');
const modalPayloadList = document.getElementById('modal-payload-list');
const modalCount = document.getElementById('modal-count');
const modalSubtitle = document.getElementById('modal-subtitle');
const modalSelectAll = document.getElementById('modal-select-all');
const modalDeselectAll = document.getElementById('modal-deselect-all');
const modalCancel = document.getElementById('modal-cancel');
const modalExecute = document.getElementById('modal-execute');

function updateModalCount() {
    const total = modalPayloadList.querySelectorAll('input[type=checkbox]').length;
    const checked = modalPayloadList.querySelectorAll('input[type=checkbox]:checked').length;
    modalCount.textContent = `${checked} of ${total} selected`;
    modalExecute.disabled = checked === 0;
}

modalSelectAll.addEventListener('click', () => {
    modalPayloadList.querySelectorAll('input[type=checkbox]').forEach(cb => cb.checked = true);
    updateModalCount();
});

modalDeselectAll.addEventListener('click', () => {
    modalPayloadList.querySelectorAll('input[type=checkbox]').forEach(cb => cb.checked = false);
    updateModalCount();
});

/**
 * tagged: Array of { payload: string, type: 'xss'|'sqli'|'custom' }
 * attackConfig: { targets: [...] }
 * onCancel: callback when user cancels
 */
function showPayloadModal(tagged, attackConfig, onCancel) {
    // Populate the list
    modalPayloadList.innerHTML = '';

    const categories = {};
    for (const item of tagged) {
        if (!categories[item.type]) categories[item.type] = [];
        categories[item.type].push(item.payload);
    }

    for (const [type, payloads] of Object.entries(categories)) {
        const catEl = document.createElement('div');
        catEl.className = 'payload-category';
        catEl.textContent = type.toUpperCase() + ' Payloads';
        modalPayloadList.appendChild(catEl);

        for (const p of payloads) {
            const row = document.createElement('label');
            row.className = 'payload-item';

            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = true;
            cb.addEventListener('change', updateModalCount);

            const badge = document.createElement('span');
            badge.className = `payload-type-badge badge-${type}`;
            badge.textContent = type.toUpperCase();

            const text = document.createElement('span');
            text.className = 'payload-item-text';
            text.textContent = p;

            row.appendChild(cb);
            row.appendChild(badge);
            row.appendChild(text);
            modalPayloadList.appendChild(row);
        }
    }

    modalSubtitle.textContent = `${tagged.length} test cases ready. Select which to run.`;
    updateModalCount();

    // Hide the native browser view so modal appears on top
    ipcRenderer.send('hide-browser-view');
    payloadModal.style.display = 'flex';

    // Cancel handler
    const cancel = () => {
        payloadModal.style.display = 'none';
        ipcRenderer.send('show-browser-view');
        modalExecute.onclick = null;
        modalCancel.onclick = null;
        if (onCancel) onCancel();
    };

    modalCancel.onclick = cancel;
    payloadModal.onclick = (e) => { if (e.target === payloadModal) cancel(); };

    // Execute handler
    modalExecute.onclick = async () => {
        // Collect only the checked payloads
        const rows = modalPayloadList.querySelectorAll('.payload-item');
        const selected = [];
        rows.forEach(row => {
            const cb = row.querySelector('input[type=checkbox]');
            const txt = row.querySelector('.payload-item-text');
            if (cb && cb.checked && txt) selected.push(txt.textContent);
        });

        payloadModal.style.display = 'none';
        ipcRenderer.send('show-browser-view');
        if (selected.length === 0) { if (onCancel) onCancel(); return; }

        appendMessage('system', `Starting attack with ${selected.length} selected payload(s)...`);

        try {
            const result = await ipcRenderer.invoke('run-attack', {
                targets: attackConfig.targets,
                customPayloads: selected
            });
            appendMessage('system', `Attack complete. ${result.successful} findings out of ${result.total} payload(s).`);
            if (result.logs && result.logs.length > 0) {
                appendMessage('system', `Logs:\n${result.logs.join('\n')}`);
            }
        } catch (e) {
            appendMessage('system', 'Attack failed: ' + e.message);
        } finally {
            btnRunAttack.disabled = false;
            btnRunAttack.textContent = 'Run Automated Attack';
        }
    };
}

// --- SECURITY INTEL UI WORKFLOW ---
const btnScanIntel = document.getElementById('btn-scan-intel');
const intelStatus = document.getElementById('intel-status');
const intelResults = document.getElementById('intel-results');

btnScanIntel.addEventListener('click', async () => {
    btnScanIntel.disabled = true;
    btnScanIntel.innerHTML = `
        <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" class="spin-icon" style="vertical-align:middle;margin-right:4px;animation:spin 1s linear infinite;"><circle cx="12" cy="12" r="10"></circle><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"></path></svg>
        Scanning...
    `;
    intelStatus.textContent = 'Scanning...';
    intelStatus.className = 'intel-status-badge';

    try {
        const intel = await ipcRenderer.invoke('collect-security-intel');
        renderIntelResults(intel);
        intelStatus.textContent = 'Scanned';
        intelStatus.className = 'intel-status-badge scanned';
    } catch (e) {
        console.error(e);
        intelStatus.textContent = 'Scan Failed';
        intelResults.innerHTML = `<div class="intel-empty" style="color:var(--danger)">Failed to run scan: ${e.message}</div>`;
    } finally {
        btnScanIntel.disabled = false;
        btnScanIntel.innerHTML = `
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" style="vertical-align:middle;margin-right:4px;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            Scan Page
        `;
    }
});

function renderIntelResults(intel) {
    intelResults.innerHTML = '';

    // Card 1: Configuration & Leakage Issues
    const issueCard = createIntelCard('Config & Header Issues', intel.issues.reduce((acc, x) => acc + x.issues.length, 0), 'var(--danger)');
    if (intel.issues.length === 0) {
        issueCard.body.innerHTML = '<div style="font-size:11px;color:var(--text-secondary);text-align:center;padding:8px 0;">No severe header configuration issues found.</div>';
    } else {
        intel.issues.forEach(iss => {
            const path = new URL(iss.url).pathname;
            const container = document.createElement('div');
            container.style.marginBottom = '8px';
            container.innerHTML = `<div style="font-size:11px;font-weight:bold;color:#f87171;word-break:break-all;margin-bottom:4px;">${path}</div>`;
            iss.issues.forEach(i => {
                const row = document.createElement('div');
                row.className = 'intel-row';
                row.innerHTML = `
                    <span class="intel-issue-badge badge-warning">Missing Header</span>
                    <span class="intel-issue-text">${i}</span>
                `;
                container.appendChild(row);
            });
            issueCard.body.appendChild(container);
        });
    }
    intelResults.appendChild(issueCard.el);

    // Card 2: Detected JavaScript Libraries
    const libCard = createIntelCard('JS Libraries', intel.libraries.length, 'var(--accent)');
    if (intel.libraries.length === 0) {
        libCard.body.innerHTML = '<div style="font-size:11px;color:var(--text-secondary);text-align:center;padding:8px 0;">No popular open-source JS libraries detected.</div>';
    } else {
        intel.libraries.forEach(lib => {
            const row = document.createElement('div');
            row.className = 'intel-row';
            row.innerHTML = `
                <span class="intel-key">${lib.name}</span>
                <span class="intel-value" style="color:#60a5fa;">${lib.version || lib.src ? 'Detected' : 'Unknown'}</span>
            `;
            libCard.body.appendChild(row);
        });
    }
    intelResults.appendChild(libCard.el);

    // Card 3: Storage Analysis
    const totalStorage = Object.keys(intel.storage.local || {}).length + Object.keys(intel.storage.session || {}).length;
    const storageCard = createIntelCard('Local & Session Storage', totalStorage, 'var(--success)');
    if (totalStorage === 0) {
        storageCard.body.innerHTML = '<div style="font-size:11px;color:var(--text-secondary);text-align:center;padding:8px 0;">No active key-value storage items detected.</div>';
    } else {
        const local = intel.storage.local || {};
        const session = intel.storage.session || {};

        if (Object.keys(local).length > 0) {
            const secHeader = document.createElement('div');
            secHeader.style.cssText = 'font-size:11px;font-weight:700;color:var(--text-secondary);margin:6px 0;';
            secHeader.textContent = 'LocalStorage';
            storageCard.body.appendChild(secHeader);
            for (const [k, v] of Object.entries(local)) {
                const row = document.createElement('div');
                row.className = 'intel-row';
                row.innerHTML = `
                    <span class="intel-key" style="max-width:120px;overflow:hidden;text-overflow:ellipsis;">${k}</span>
                    <span class="intel-value">${v}</span>
                `;
                storageCard.body.appendChild(row);
            }
        }
        if (Object.keys(session).length > 0) {
            const secHeader = document.createElement('div');
            secHeader.style.cssText = 'font-size:11px;font-weight:700;color:var(--text-secondary);margin:6px 0;';
            secHeader.textContent = 'SessionStorage';
            storageCard.body.appendChild(secHeader);
            for (const [k, v] of Object.entries(session)) {
                const row = document.createElement('div');
                row.className = 'intel-row';
                row.innerHTML = `
                    <span class="intel-key" style="max-width:120px;overflow:hidden;text-overflow:ellipsis;">${k}</span>
                    <span class="intel-value">${v}</span>
                `;
                storageCard.body.appendChild(row);
            }
        }
    }
    intelResults.appendChild(storageCard.el);

    // Card 4: Cookie Auditor
    const cookieCard = createIntelCard('Cookies', intel.cookies.length, 'purple');
    if (intel.cookies.length === 0) {
        cookieCard.body.innerHTML = '<div style="font-size:11px;color:var(--text-secondary);text-align:center;padding:8px 0;">No cookies set for this page.</div>';
    } else {
        intel.cookies.forEach(c => {
            const item = document.createElement('div');
            item.style.marginBottom = '10px';
            item.innerHTML = `
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                    <span style="font-size:11px;font-weight:bold;color:var(--text-primary);">${c.name}</span>
                    <div style="display:flex;gap:4px;">
                        ${c.httpOnly ? '<span class="intel-issue-badge badge-info" style="font-size:8px;padding:1px 4px;">HttpOnly</span>' : ''}
                        ${c.secure ? '<span class="intel-issue-badge badge-info" style="font-size:8px;padding:1px 4px;background:rgba(16,185,129,0.15);color:#34d399;">Secure</span>' : ''}
                    </div>
                </div>
                <div class="intel-row">
                    <span class="intel-key">Value</span>
                    <span class="intel-value">${c.value}</span>
                </div>
            `;
            cookieCard.body.appendChild(item);
        });
    }
    intelResults.appendChild(cookieCard.el);
}

function createIntelCard(title, count, badgeBg) {
    const el = document.createElement('div');
    el.className = 'intel-card open';

    const header = document.createElement('div');
    header.className = 'intel-card-header';

    const left = document.createElement('div');
    left.className = 'intel-card-title';
    left.innerHTML = `
        <span class="intel-card-arrow">▶</span>
        <span>${title}</span>
        ${count > 0 ? `<span class="intel-card-count" style="background:${badgeBg};color:white;">${count}</span>` : ''}
    `;

    header.appendChild(left);
    el.appendChild(header);

    const body = document.createElement('div');
    body.className = 'intel-card-body';
    el.appendChild(body);

    header.addEventListener('click', () => {
        el.classList.toggle('open');
    });

    return { el, body };
}

// Add animation frame styling for spinner icon to index.html if not already exists, or just use custom rotate inside styles.css
const spinStyle = document.createElement('style');
spinStyle.innerHTML = `
@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
.spin-icon {
    animation: spin 1s linear infinite;
}
`;
document.head.appendChild(spinStyle);

