const { app, BrowserWindow, WebContentsView, ipcMain, shell, session } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const LlmService = require('./llmService');

let mainWindow;
let view;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        title: 'AI DAST Browser',
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false, // For simplicity in this local app. In production, use preload scripts.
        }
    });

    mainWindow.loadFile('index.html');

    // Create the View for the actual web browsing
    // contextIsolation:false + preload allows our xss-preload.js to intercept window.alert()
    view = new WebContentsView({
        webPreferences: {
            contextIsolation: false,
            webSecurity: false, // Allow cross-origin and local execution for testing
            preload: path.join(__dirname, 'xss-preload.js')
        }
    });
    mainWindow.contentView.addChildView(view);

    // Position the view (taking into account the 50px top nav and 350px sidebar)
    // We will resize it dynamically when the window resizes
    // ---------- Security Intel Helpers ----------
    const securityIntel = {
        cookies: [],
        storage: {},
        libraries: [],
        responseHeaders: [],
        issues: []
    };

    // Capture response headers for each request
    const networkData = new Map();

    // Capture response headers for each request
    const capturedHeaders = [];
    view.webContents.session.webRequest.onHeadersReceived((details, callback) => {
        capturedHeaders.push({ url: details.url, responseHeaders: details.responseHeaders });
        
        const data = networkData.get(details.id);
        if (data) {
            data.responseHeaders = details.responseHeaders;
            data.statusCode = details.statusCode;
        }

        // Disable CSP and XSS protection to allow attacks to execute
        const headers = { ...details.responseHeaders };
        for (const key in headers) {
            const lower = key.toLowerCase();
            if (lower === 'content-security-policy' || lower === 'x-xss-protection') {
                delete headers[key];
            }
        }
        
        callback({ cancel: false, responseHeaders: headers });
    });

    view.webContents.session.webRequest.onCompleted((details) => {
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('network-completed', {
                id: details.id,
                statusCode: details.statusCode
            });
        }
    });

    // Network Tab listeners
    view.webContents.session.webRequest.onBeforeRequest((details, callback) => {
        networkData.set(details.id, {
            id: details.id,
            method: details.method,
            url: details.url,
            resourceType: details.resourceType,
            requestBody: details.uploadData ? details.uploadData.map(d => {
                if (d.bytes) return d.bytes.toString();
                return 'Binary Data';
            }).join('\n') : null,
            status: 'pending'
        });

        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('network-request', {
                id: details.id,
                method: details.method,
                url: details.url,
                resourceType: details.resourceType,
                status: 'pending'
            });
        }
        callback({ cancel: false });
    });

    view.webContents.session.webRequest.onSendHeaders((details) => {
        const data = networkData.get(details.id);
        if (data) {
            data.requestHeaders = details.requestHeaders;
        }
    });

    view.webContents.session.webRequest.onErrorOccurred((details) => {
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('network-error', {
                id: details.id,
                error: details.error
            });
        }
    });

    ipcMain.on('show-network-details', (event, id) => {
        const data = networkData.get(id);
        if (!data) return;

        const detailsWindow = new BrowserWindow({
            width: 800,
            height: 600,
            title: 'Network Details - ' + data.url,
            webPreferences: {
                nodeIntegration: true,
                contextIsolation: false
            }
        });
        
        detailsWindow.setMenuBarVisibility(false);

        const htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: monospace; padding: 20px; background: #0f172a; color: #f8fafc; }
                    h2 { color: #3b82f6; border-bottom: 1px solid #334155; padding-bottom: 5px; }
                    h3 { color: #10b981; margin-top: 20px; }
                    .section { margin-bottom: 20px; background: #1e293b; padding: 15px; border-radius: 8px; border: 1px solid #334155; overflow-wrap: break-word; }
                    .header-name { color: #93c5fd; font-weight: bold; }
                    pre { white-space: pre-wrap; word-wrap: break-word; font-family: inherit; margin: 0; }
                </style>
            </head>
            <body>
                <h2>Request</h2>
                <div class="section">
                    <strong>URL:</strong> ${data.url}<br>
                    <strong>Method:</strong> ${data.method}<br>
                    <strong>Resource Type:</strong> ${data.resourceType}<br>
                </div>
                
                <h3>Request Headers</h3>
                <div class="section">
                    ${Object.entries(data.requestHeaders || {}).map(([k, v]) => `<span class="header-name">${k}:</span> ${v}<br>`).join('')}
                </div>

                ${data.requestBody ? `
                <h3>Request Body</h3>
                <div class="section">
                    <pre>${data.requestBody.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
                </div>` : ''}

                <h2>Response</h2>
                <h3>Response Headers</h3>
                <div class="section">
                    <strong>Status Code:</strong> ${data.statusCode || 'Unknown'}<br>
                    ${Object.entries(data.responseHeaders || {}).map(([k, v]) => `<span class="header-name">${k}:</span> ${v}<br>`).join('')}
                </div>
            </body>
            </html>
        `;

        detailsWindow.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(htmlContent));
    });

    // Helper to get cookies for current page
    async function getCookies() {
        const url = view && view.webContents ? view.webContents.getURL() : '';
        if (!url) return [];
        return await view.webContents.session.cookies.get({ url });
    }

    // Helper to get localStorage & sessionStorage values
    async function getStorage() {
        if (!view || !view.webContents) return {};
        const script = `({
            local: Object.fromEntries(Object.entries(localStorage)),
            session: Object.fromEntries(Object.entries(sessionStorage))
        })`;
        try {
            return await view.webContents.executeJavaScript(script);
        } catch {
            return {};
        }
    }

    // Detect common JS libraries by checking globals & script src patterns
    async function detectLibraries() {
        if (!view || !view.webContents) return [];
        const script = `(() => {
            const libs = [];
            if (window.jQuery) libs.push({ name: 'jQuery', version: $.fn.jquery });
            if (window._) libs.push({ name: 'Underscore/Lodash', version: _.VERSION });
            if (window.React) libs.push({ name: 'React', version: React.version });
            if (window.angular) libs.push({ name: 'AngularJS', version: angular.version.full });
            // Scan script tags for known src patterns
            document.querySelectorAll('script[src]').forEach(s => {
                const src = s.src.toLowerCase();
                if (src.includes('jquery')) libs.push({ name: 'jQuery', src });
                if (src.includes('react')) libs.push({ name: 'React', src });
                if (src.includes('angular')) libs.push({ name: 'Angular', src });
                if (src.includes('lodash') || src.includes('underscore')) libs.push({ name: 'Lodash/Underscore', src });
            });
            return libs;
        })();`;
        try {
            return await view.webContents.executeJavaScript(script);
        } catch {
            return [];
        }
    }

    // Simple security header checks
    function checkSecurityHeaders(headers) {
        const issues = [];
        const hdr = {};
        for (const [k, v] of Object.entries(headers)) {
            hdr[k.toLowerCase()] = Array.isArray(v) ? v[0] : v;
        }
        if (!hdr['x-content-type-options']) issues.push('Missing X-Content-Type-Options');
        if (!hdr['x-frame-options']) issues.push('Missing X-Frame-Options');
        if (!hdr['strict-transport-security']) issues.push('Missing Strict-Transport-Security');
        if (!hdr['content-security-policy']) issues.push('Missing Content-Security-Policy');
        return issues;
    }

    // IPC to collect all intel
    ipcMain.handle('collect-security-intel', async () => {
        const cookies = await getCookies();
        const storage = await getStorage();
        const libraries = await detectLibraries();
        const headers = capturedHeaders.slice(); // copy current list
        const issues = [];
        headers.forEach(h => {
            const iss = checkSecurityHeaders(h.responseHeaders);
            if (iss.length) issues.push({ url: h.url, issues: iss });
        });
        // Reset capturedHeaders for next run
        capturedHeaders.length = 0;
        return { cookies, storage, libraries, headers, issues };
    });

    const updateViewBounds = () => {
        const bounds = mainWindow.getContentBounds();
        view.setBounds({
            x: 0,
            y: 50,
            width: bounds.width - 350,
            height: bounds.height - 50
        });
    };

    mainWindow.on('resize', updateViewBounds);
    mainWindow.once('ready-to-show', updateViewBounds);

    // Allow renderer to hide/show the native browser view (needed for modals)
    ipcMain.on('hide-browser-view', () => view.setVisible(false));
    ipcMain.on('show-browser-view', () => view.setVisible(true));

    // Notify renderer when a new page loads
    view.webContents.on('did-finish-load', () => {
        const url = view.webContents.getURL();
        if (url !== 'about:blank') {
            mainWindow.webContents.send('page-loaded', url);
        }
    });

    // Initial default page
    view.webContents.loadURL('about:blank');
}

app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// --- IPC Handlers for Browser Navigation ---
ipcMain.handle('navigate', async (event, url) => {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
    }
    await view.webContents.loadURL(url);
    return view.webContents.getURL();
});

ipcMain.on('go-back', () => view.webContents.goBack());
ipcMain.on('go-forward', () => view.webContents.goForward());
ipcMain.on('reload', () => view.webContents.reload());

// --- IPC Handlers for DAST Engine ---
ipcMain.handle('extract-context', async () => {
    // Inject JS into the target page to extract forms and inputs
    const code = `
        (() => {
            const getSelector = (el) => {
                if (!el) return null;
                let sel = el.tagName.toLowerCase();
                if (el.id) sel += '#' + el.id;
                else if (el.name) sel += '[name="' + el.name + '"]';
                else if (el.className && typeof el.className === 'string') {
                    const cls = el.className.trim().split(/\\s+/).join('.');
                    if (cls) sel += '.' + cls;
                }
                return sel;
            };

            const extractElement = (el) => ({
                tag: el.tagName.toLowerCase(),
                type: el.type || undefined,
                name: el.name || undefined,
                id: el.id || undefined,
                placeholder: el.placeholder || undefined,
                text: (el.tagName === 'BUTTON' && el.textContent) ? el.textContent.trim().substring(0, 50) : undefined,
                selector: getSelector(el)
            });

            const allInputs = Array.from(document.querySelectorAll('input:not([type="hidden"]), textarea, select')).map(extractElement);
            const allButtons = Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"]')).map(extractElement);
            
            const forms = Array.from(document.forms).map(f => {
                const inputs = Array.from(f.querySelectorAll('input:not([type="hidden"]), textarea, select')).map(extractElement);
                const buttons = Array.from(f.querySelectorAll('button, input[type="submit"], input[type="button"]')).map(extractElement);
                return { action: f.action, method: f.method, selector: getSelector(f), inputs, buttons };
            });

            return JSON.stringify({
                url: window.location.href,
                title: document.title,
                allInputs: allInputs,
                allButtons: allButtons,
                forms: forms
            });
        })();
    `;
    try {
        const result = await view.webContents.executeJavaScript(code);
        return JSON.parse(result);
    } catch (err) {
        console.error("Failed to extract context:", err);
        return { error: err.message };
    }
});

ipcMain.handle('llm-chat', async (event, model, prompt) => {
    try {
        const response = await LlmService.generate(model, prompt);
        return response;
    } catch (err) {
        console.error("LLM Error:", err);
        return "Error connecting to local LLM: " + err.message;
    }
});

ipcMain.handle('execute-payload', async (event, javascriptPayload) => {
    try {
        // Warning: This directly executes JS in the context of the viewed page
        await view.webContents.executeJavaScript(javascriptPayload);
        return { success: true };
    } catch (err) {
        return { success: false, error: err.message };
    }
});

// --- NEW: Attack Configuration & Execution ---

ipcMain.handle('start-tagging', async (event, type) => {
    // Inject a script that allows the user to click an element and returns its CSS selector
    const code = `
        new Promise((resolve) => {
            const overlay = document.createElement('div');
            Object.assign(overlay.style, {
                position: 'fixed', top: '0', left: '0', width: '100%', height: '100%',
                backgroundColor: 'rgba(59, 130, 246, 0.1)', zIndex: '999999', cursor: 'crosshair'
            });
            document.body.appendChild(overlay);

            const highlight = document.createElement('div');
            Object.assign(highlight.style, {
                position: 'absolute', pointerEvents: 'none', border: '2px solid #3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.2)', zIndex: '1000000', transition: 'all 0.1s'
            });
            document.body.appendChild(highlight);

            const mouseMoveHandler = (e) => {
                overlay.style.pointerEvents = 'none'; // Temporarily disable to get element underneath
                const target = document.elementFromPoint(e.clientX, e.clientY);
                overlay.style.pointerEvents = 'auto'; // Re-enable
                
                if (target) {
                    const rect = target.getBoundingClientRect();
                    Object.assign(highlight.style, {
                        top: rect.top + window.scrollY + 'px', left: rect.left + window.scrollX + 'px',
                        width: rect.width + 'px', height: rect.height + 'px'
                    });
                }
            };

            const clickHandler = (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                overlay.style.pointerEvents = 'none';
                const target = document.elementFromPoint(e.clientX, e.clientY);
                
                // Generate a simple CSS selector
                let selector = target.tagName.toLowerCase();
                if (target.id) {
                    selector += '#' + target.id;
                } else if (target.name) {
                    selector += '[name="' + target.name + '"]';
                } else if (target.className && typeof target.className === 'string') {
                    selector += '.' + target.className.trim().split(/\\s+/).join('.');
                }
                
                document.body.removeChild(overlay);
                document.body.removeChild(highlight);
                document.removeEventListener('mousemove', mouseMoveHandler);
                document.removeEventListener('click', clickHandler, true);
                resolve(selector);
            };

            document.addEventListener('mousemove', mouseMoveHandler);
            document.addEventListener('click', clickHandler, true);
        });
    `;
    try {
        const selector = await view.webContents.executeJavaScript(code);
        return selector;
    } catch (err) {
        console.error("Tagging failed:", err);
        return null;
    }
});

ipcMain.handle('auto-detect-form', async () => {
    const code = `
        (() => {
            const forms = Array.from(document.forms);
            if (forms.length > 0) {
                const f = forms[0];
                const inputs = Array.from(f.querySelectorAll('input[type="text"], input[type="search"], input[type="email"], input[type="password"], input:not([type])'));
                const submit = f.querySelector('button[type="submit"], input[type="submit"], button');
                
                const getSelector = (el) => {
                    if (!el) return null;
                    let sel = el.tagName.toLowerCase();
                    if (el.id) sel += '#' + el.id;
                    else if (el.name) sel += '[name="' + el.name + '"]';
                    return sel;
                };
                
                return { inputs: inputs.map(getSelector).filter(Boolean), submit: getSelector(submit) };
            }
            return { inputs: [], submit: null };
        })();
    `;
    try {
        return await view.webContents.executeJavaScript(code);
    } catch (err) {
        return { inputs: [], submit: null };
    }
});

ipcMain.handle('load-payloads', async () => {
    try {
        const str = fs.readFileSync(path.join(__dirname, 'payloads.json'), 'utf8');
        return JSON.parse(str);
    } catch (e) {
        return { xss: [], sqli: [] };
    }
});

ipcMain.handle('run-attack', async (event, { targets, customPayloads }) => {
    let allPayloads = [];
    
    if (customPayloads && Array.isArray(customPayloads)) {
        allPayloads = customPayloads;
    } else {
        try {
            const payloadStr = fs.readFileSync(path.join(__dirname, 'payloads.json'), 'utf8');
            const payloads = JSON.parse(payloadStr);
            allPayloads = [...(payloads.xss || []), ...(payloads.sqli || [])];
        } catch (err) {
            throw new Error("Could not load payloads: " + err.message);
        }
    }
    const logs = [];
    const executionData = []; // To store payload, status, and screenshot
    let successful = 0;

    for (const target of targets || []) {
        const { inputSelectors, submitSelector } = target;
        if (!inputSelectors || !submitSelector || inputSelectors.length === 0) continue;
        
        logs.push(`\n--- Attacking target (Inputs: ${inputSelectors.length}, Submit: ${submitSelector}) ---`);
        
        // Capture the original URL to reload for each input/payload combination
        const targetUrl = view.webContents.getURL();

        for (let i = 0; i < inputSelectors.length; i++) {
            const currentInputSelector = inputSelectors[i];
            logs.push(`\n--- Testing Input: ${currentInputSelector} ---`);
            
            for (const payload of allPayloads) {
                // Ensure we are on the target URL
                if (view.webContents.getURL() !== targetUrl) {
                    await view.webContents.loadURL(targetUrl);
                    await new Promise(r => setTimeout(r, 1500)); // wait for load
                }

                logs.push(`Testing payload: ${payload}`);

                // Capture pre-submit URL and page title for SQLi redirect detection
                const urlBefore = view.webContents.getURL();
                const titleBefore = view.webContents.getTitle();

                // Listen for XSS alerts fired via preload IPC (survives page navigation)
                let alertFiredByPreload = false;
                const xssHandler = (event, data) => {
                    alertFiredByPreload = true;
                    event.returnValue = null; // required for sendSync
                };
                ipcMain.on('xss-alert-fired', xssHandler);

                const injectCode = `
                    (() => {
                        let submitEl = document.querySelector(${JSON.stringify(submitSelector)});
                        const allSelectors = ${JSON.stringify(inputSelectors)};
                        const targetSelector = ${JSON.stringify(currentInputSelector)};
                        
                        if (!submitEl && allSelectors.length > 0) {
                            const firstInput = document.querySelector(allSelectors[0]);
                            if (firstInput && firstInput.form) submitEl = firstInput.form;
                        }
                        if (!submitEl) return { error: 'Submit element not found' };

                        let targetInputFilled = false;
                        for (const sel of allSelectors) {
                            const inputEl = document.querySelector(sel);
                            if (inputEl) {
                                if (sel === targetSelector) {
                                    inputEl.value = ${JSON.stringify(payload)};
                                    targetInputFilled = true;
                                } else {
                                    // Fill other inputs with dummy data to pass validation
                                    if (inputEl.type === 'email') inputEl.value = 'test@example.com';
                                    else if (inputEl.type === 'number') inputEl.value = '1';
                                    else inputEl.value = 'test';
                                }
                            }
                        }
                        if (!targetInputFilled) return { error: 'Target input element not found' };

                        if (submitEl.tagName.toLowerCase() === 'form') {
                            submitEl.submit();
                        } else {
                            submitEl.click();
                        }
                        return { submitted: true };
                    })();
                `;

            try {
                // Inject & submit — synchronous IIFE, won't break on navigation
                const injResult = await view.webContents.executeJavaScript(injectCode).catch(e => ({ error: e.message }));

                if (injResult && injResult.error) {
                    logs.push('  -> Failed: ' + injResult.error);
                    executionData.push({ payload, status: 'Failed: ' + injResult.error, screenshot: null });
                    ipcMain.removeListener('xss-alert-fired', xssHandler);
                    continue;
                }

                // Wait for page to settle (handles form redirect + XSS execution)
                await new Promise(r => setTimeout(r, 2000));

                // Capture screenshot after page settles
                let screenshotDataUrl = null;
                try {
                    const image = await view.webContents.capturePage();
                    screenshotDataUrl = image.toDataURL();
                } catch (_) { /* page may still be loading */ }

                // --- Multi-signal Vulnerability Detection ---
                const urlAfter = view.webContents.getURL();
                const titleAfter = view.webContents.getTitle();
                const urlChanged = urlAfter !== urlBefore;
                const titleChanged = titleAfter !== titleBefore;

                // Check page content for SQL error signatures
                let sqlErrorFound = false;
                let sqlErrorMsg = '';
                try {
                    const bodyText = await view.webContents.executeJavaScript('document.body ? document.body.innerText : ""').catch(() => '');
                    const sqlPatterns = [
                        /sql syntax/i, /mysql_fetch/i, /ORA-\d{4,}/i,
                        /unclosed quotation/i, /sqlexception/i, /pg_query/i,
                        /syntax error.*sql/i, /you have an error in your sql/i,
                        /warning.*mysql/i, /odbc.*driver/i, /jdbc.*error/i,
                        /microsoft.*ole.*db.*sql/i
                    ];
                    for (const p of sqlPatterns) {
                        if (p.test(bodyText)) {
                            sqlErrorFound = true;
                            sqlErrorMsg = bodyText.match(p)[0];
                            break;
                        }
                    }
                } catch (_) {}

                // Determine finding
                let statusStr;
                let isVuln = false;

                if (alertFiredByPreload) {
                    statusStr = 'VULNERABILITY FOUND! (XSS Alert Triggered)';
                    isVuln = true;
                } else if (sqlErrorFound) {
                    statusStr = `VULNERABILITY FOUND! (SQL Error: "${sqlErrorMsg}")`;
                    isVuln = true;
                } else if (urlChanged) {
                    statusStr = `POSSIBLE SQLi BYPASS! (Redirect: ${urlBefore} → ${urlAfter})`;
                    isVuln = true;
                    logs.push(`  [URL Changed] ${urlBefore} -> ${urlAfter}`);
                } else if (titleChanged) {
                    statusStr = `POSSIBLE SQLi BYPASS! (Page title changed: "${titleBefore}" → "${titleAfter}")`;
                    isVuln = true;
                } else {
                    statusStr = 'No immediate execution detected.';
                }

                if (isVuln) successful++;
                logs.push('  -> ' + statusStr);
                executionData.push({ payload, status: statusStr, screenshot: screenshotDataUrl });

            } catch (err) {
                logs.push('  -> Execution error: ' + err.message);
                executionData.push({ payload, status: 'Error: ' + err.message, screenshot: null });
            } finally {
                ipcMain.removeListener('xss-alert-fired', xssHandler);
            }
            
            await new Promise(r => setTimeout(r, 500));
        }
        }
    }
    
    // Generate PDF Report
    try {
        const reportsDir = path.join(__dirname, 'reports');
        fs.mkdirSync(reportsDir, { recursive: true });
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const pdfPath = path.join(reportsDir, `ScanReport_${timestamp}.pdf`);
        
        let htmlContent = `
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; color: #333; }
                h1 { color: #2563eb; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }
                .summary { background: #f8fafc; padding: 15px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #e2e8f0; }
                .payload-block { page-break-inside: avoid; border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
                .payload-text { font-family: monospace; background: #f1f5f9; padding: 10px; border-radius: 4px; overflow-wrap: break-word; font-size: 14px; }
                .status-success { color: #dc2626; font-weight: bold; }
                .status-fail { color: #64748b; }
                .screenshot { max-width: 100%; border: 1px solid #e2e8f0; border-radius: 4px; margin-top: 10px; }
            </style>
        </head>
        <body>
            <h1>AI-DAST Security Scan Report</h1>
            <div class="summary">
                <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
                <p><strong>Total Payloads Tested:</strong> ${allPayloads.length}</p>
                <p><strong>Vulnerabilities Found:</strong> <span style="color: ${successful > 0 ? '#dc2626' : '#16a34a'}; font-weight: bold;">${successful}</span></p>
            </div>
            
            <h2>Execution Details</h2>
        `;
        
        for (let i = 0; i < executionData.length; i++) {
            const data = executionData[i];
            const isVuln = data.status.includes("VULNERABILITY FOUND");
            const statusClass = isVuln ? 'status-success' : 'status-fail';
            
            htmlContent += `
            <div class="payload-block">
                <p><strong>Step ${i + 1}</strong></p>
                <p><strong>Payload:</strong></p>
                <div class="payload-text">${data.payload.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
                <p><strong>Status:</strong> <span class="${statusClass}">${data.status}</span></p>
                ${data.screenshot ? `<img class="screenshot" src="${data.screenshot}" />` : '<p><i>No screenshot available</i></p>'}
            </div>
            `;
        }
        
        htmlContent += `</body></html>`;
        
        // Create an offscreen window to render the HTML to PDF
        const offscreenWindow = new BrowserWindow({
            show: false,
            webPreferences: {
                nodeIntegration: false,
                contextIsolation: true
            }
        });
        
        await offscreenWindow.loadURL('about:blank');
        await offscreenWindow.webContents.executeJavaScript(`
            document.open();
            document.write(${JSON.stringify(htmlContent)});
            document.close();
        `);
        
        // Wait briefly for images to render
        await new Promise(r => setTimeout(r, 1000));
        
        const pdfData = await offscreenWindow.webContents.printToPDF({
            printBackground: true,
            margin: { top: 1, bottom: 1, left: 1, right: 1 }
        });
        
        fs.writeFileSync(pdfPath, pdfData);
        offscreenWindow.destroy();
        
        logs.push(`\n[System] PDF Report saved to: ${pdfPath}`);
        
        // Notify the renderer so the Reports tab auto-refreshes
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('report-generated');
        }
    } catch (pdfErr) {
        logs.push(`\n[System] Error generating PDF report: ${pdfErr.message}`);
        console.error("PDF generation error:", pdfErr);
    }

    return { total: allPayloads.length, successful, logs };
});

// --- IPC Handlers for Reports ---
ipcMain.handle('list-reports', async () => {
    const reportsDir = path.join(__dirname, 'reports');
    if (!fs.existsSync(reportsDir)) {
        return [];
    }
    
    try {
        const files = fs.readdirSync(reportsDir).filter(f => f.endsWith('.pdf'));
        const reports = files.map(file => {
            const filePath = path.join(reportsDir, file);
            const stats = fs.statSync(filePath);
            return {
                name: file,
                path: filePath,
                mtime: stats.mtimeMs
            };
        });
        
        // Sort by newest first
        return reports.sort((a, b) => b.mtime - a.mtime);
    } catch (err) {
        console.error("Error reading reports directory:", err);
        return [];
    }
});

ipcMain.on('open-report', (event, filePath) => {
    shell.openPath(filePath);
});
