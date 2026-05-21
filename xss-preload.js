/**
 * xss-preload.js
 * Runs in the browsed page's JS context before any page script.
 * Overrides window.alert/confirm/prompt to intercept XSS payloads
 * and notify the main process via synchronous IPC.
 */
const { ipcRenderer } = require('electron');

const _origAlert   = window.alert.bind(window);
const _origConfirm = window.confirm.bind(window);
const _origPrompt  = window.prompt.bind(window);

window.alert = function(msg) {
    ipcRenderer.sendSync('xss-alert-fired', { type: 'alert', message: String(msg) });
    // Do NOT call _origAlert — we don't want any GTK dialog shown
};

window.confirm = function(msg) {
    ipcRenderer.sendSync('xss-alert-fired', { type: 'confirm', message: String(msg) });
    return false;
};

window.prompt = function(msg, defaultVal) {
    ipcRenderer.sendSync('xss-alert-fired', { type: 'prompt', message: String(msg) });
    return null;
};
