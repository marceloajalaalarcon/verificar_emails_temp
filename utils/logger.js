/**
 * Structured JSON Logger
 * Writes verification logs to logs/verification-YYYY-MM-DD.log
 */

const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'logs');

function ensureLogDir() {
    if (!fs.existsSync(LOG_DIR)) {
        fs.mkdirSync(LOG_DIR, { recursive: true });
    }
}

function getLogFilename() {
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    return path.join(LOG_DIR, `verification-${today}.log`);
}

function logVerification(data) {
    try {
        ensureLogDir();
        const entry = {
            timestamp: new Date().toISOString(),
            email: data.email,
            score: data.score,
            cached: data.cached || false,
            responseTimeMs: data.responseTimeMs || null,
            reasons: data.reasons || []
        };
        const line = JSON.stringify(entry) + '\n';
        fs.appendFileSync(getLogFilename(), line, 'utf8');
    } catch (err) {
        console.error('[Logger] Failed to write log:', err.message);
    }
}

module.exports = { logVerification };
