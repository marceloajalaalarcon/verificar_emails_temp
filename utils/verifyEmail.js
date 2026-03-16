/**
 * Core Email Verification Logic
 * Extracted from routes/verify.js for reuse in single and bulk endpoints.
 *
 * Fixes applied:
 *  - Removed `new Promise(async ...)` anti-pattern
 *  - Single MX DNS resolution (passed to SMTP check)
 *  - Catch-All detection reuses SMTP session
 *  - Greylisting retry support
 *  - Configurable SMTP timeout via .env
 *  - WHOIS domain age penalty (optional)
 *  - Cache integration
 *  - Structured logging
 *  - Metrics tracking
 */

const dns = require('dns').promises;
const net = require('net');
const { isDisposable } = require('./fetchLists');
const cache = require('./cache');
const { logVerification } = require('./logger');
const { recordVerification } = require('./metrics');
const { getDomainAge, WHOIS_ENABLED } = require('./whois');

// --- Config from .env ---
const SMTP_TIMEOUT = parseInt(process.env.SMTP_TIMEOUT_MS) || 4000;
const GREYLISTING_RETRY = process.env.GREYLISTING_RETRY !== 'false'; // default true
const GREYLISTING_DELAY = parseInt(process.env.GREYLISTING_DELAY_MS) || 3000;

// --- Heuristics ---

const ROLE_EMAILS = new Set([
    'admin', 'support', 'info', 'contact', 'sales', 'marketing', 'help',
    'webmaster', 'postmaster', 'hostmaster', 'abuse', 'noreply', 'no-reply'
]);

function isRoleBased(user) {
    return ROLE_EMAILS.has(user.toLowerCase());
}

function isGibberish(user) {
    const digits = user.replace(/[^0-9]/g, '').length;
    const length = user.length;
    if (length > 6 && (digits / length) > 0.4) return true;
    return false;
}

// --- SMTP Check (fixed: no more new Promise(async ...)) ---

/**
 * Performs SMTP handshake to verify if a mailbox exists.
 * Optionally tests catch-all by also sending RCPT TO for a random address
 * in the SAME session.
 *
 * @param {string} mxHost - MX server hostname
 * @param {string} domain - Email domain
 * @param {string} email - Email to verify
 * @param {object} options
 * @param {boolean} options.checkCatchAll - Also test a random address
 * @returns {Promise<{smtpValid: boolean, isCatchAll: boolean, greylisted: boolean}>}
 */
function checkSmtp(mxHost, domain, email, options = {}) {
    const { checkCatchAll = false } = options;

    return new Promise((resolve) => {
        const socket = net.createConnection(25, mxHost);
        let step = 0;
        let smtpValid = false;
        let isCatchAll = false;
        let greylisted = false;

        socket.setTimeout(SMTP_TIMEOUT);

        socket.on('data', (data) => {
            const response = data.toString();

            if (response.startsWith('220') && step === 0) {
                socket.write(`HELO ${domain}\r\n`);
                step++;
            } else if (response.startsWith('250') && step === 1) {
                socket.write(`MAIL FROM:<check@${domain}>\r\n`);
                step++;
            } else if (response.startsWith('250') && step === 2) {
                socket.write(`RCPT TO:<${email}>\r\n`);
                step++;
            } else if ((response.startsWith('250') || response.startsWith('251')) && step === 3) {
                smtpValid = true;
                if (checkCatchAll) {
                    // Test catch-all in the same session
                    const randomUser = 'rx' + Math.random().toString(36).substring(7);
                    socket.write(`RCPT TO:<${randomUser}@${domain}>\r\n`);
                    step++;
                } else {
                    socket.write('QUIT\r\n');
                    step = 99;
                }
            } else if ((response.startsWith('250') || response.startsWith('251')) && step === 4) {
                // Catch-all: random address also accepted
                isCatchAll = true;
                socket.write('QUIT\r\n');
                step = 99;
            } else if (response.startsWith('4') && step === 3) {
                // 4xx = greylisting or temporary rejection
                greylisted = true;
                socket.write('QUIT\r\n');
                step = 99;
            } else if (step === 4) {
                // Random address rejected = NOT catch-all (good)
                socket.write('QUIT\r\n');
                step = 99;
            } else if (step === 99) {
                // After QUIT, ignore further data
            } else {
                socket.end();
            }
        });

        socket.on('error', () => resolve({ smtpValid: false, isCatchAll: false, greylisted: false }));
        socket.on('timeout', () => { socket.destroy(); resolve({ smtpValid: false, isCatchAll: false, greylisted: false }); });
        socket.on('end', () => resolve({ smtpValid, isCatchAll, greylisted }));
        socket.on('close', () => resolve({ smtpValid, isCatchAll, greylisted }));
    });
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// --- Main Verification Function ---

async function verifyEmail(email) {
    const startTime = Date.now();

    // 0. Check cache first
    const cachedResult = cache.get(email);
    if (cachedResult) {
        recordVerification(cachedResult);
        logVerification({ ...cachedResult, responseTimeMs: Date.now() - startTime });
        return cachedResult;
    }

    // 1. Syntax Check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        const result = {
            email,
            isValidSyntax: false,
            score: 0,
            reasons: ['Invalid email syntax']
        };
        recordVerification(result);
        logVerification({ ...result, responseTimeMs: Date.now() - startTime });
        return result;
    }

    const [user, domain] = email.split('@');

    // 2. PHASE 1: Blocklist Check (Kill Switch)
    const disposable = isDisposable(domain);
    if (disposable) {
        const result = {
            email,
            domain,
            isValidSyntax: true,
            isDisposable: true,
            score: 0,
            reasons: ['Blocked by Disposable List (Phase 1)']
        };
        cache.set(email, result);
        recordVerification(result);
        logVerification({ ...result, responseTimeMs: Date.now() - startTime });
        return result;
    }

    // 3. PHASE 2: Deep Verification
    let score = 0;
    let reasons = [];

    // Baseline: Syntax passed (+10)
    score += 10;
    reasons.push('Valid Syntax (+10)');

    // Not in Blocklist (+30)
    score += 30;
    reasons.push('Domain Trusted (Not in Blocklist) (+30)');

    // MX Check — resolved ONCE, passed to SMTP
    let hasMx = false;
    let mxRecords = null;
    try {
        mxRecords = await dns.resolveMx(domain);
        hasMx = mxRecords && mxRecords.length > 0;
    } catch (e) { hasMx = false; }

    if (hasMx) {
        score += 20;
        reasons.push('MX Records Valid (+20)');
    } else {
        reasons.push('MX Records Missing (+0)');
    }

    // Heuristics
    const roleBased = isRoleBased(user);
    const gibberish = isGibberish(user);

    if (!roleBased) {
        score += 5;
        reasons.push('Personal Address (Not Role-Based) (+5)');
    } else {
        reasons.push('Role-Based Address (admin/support) (+0)');
    }

    if (!gibberish) {
        score += 5;
        reasons.push('User looks legitimate (Not Gibberish) (+5)');
    } else {
        reasons.push('User looks random/gibberish (+0)');
    }

    // SMTP Deep Check (Only if MX passed)
    let smtpValid = false;
    let isCatchAll = false;

    if (hasMx) {
        const mxHost = mxRecords.sort((a, b) => a.priority - b.priority)[0].exchange;

        // Single SMTP session: verify email + catch-all in one connection
        let smtpResult = await checkSmtp(mxHost, domain, email, { checkCatchAll: true });

        // Greylisting retry: if we got a 4xx, wait and try again once
        if (smtpResult.greylisted && GREYLISTING_RETRY) {
            reasons.push(`Greylisting detected, retrying after ${GREYLISTING_DELAY}ms...`);
            await sleep(GREYLISTING_DELAY);
            smtpResult = await checkSmtp(mxHost, domain, email, { checkCatchAll: true });
        }

        smtpValid = smtpResult.smtpValid;
        isCatchAll = smtpResult.isCatchAll;
    }

    if (smtpValid) {
        if (isCatchAll) {
            score -= 40;
            reasons.push('CRITICAL: Domain is Catch-All (Accepts random users) (-40)');
            reasons.push('SMTP Handshake: Mailbox technically exists, but so does everyone else (+0)');
        } else {
            score += 30;
            reasons.push('SMTP Handshake: Mailbox Exists (+30)');
        }
    } else {
        reasons.push('SMTP Handshake: Mailbox not verified or connection failed (+0)');
    }

    // WHOIS Domain Age Check (optional)
    if (WHOIS_ENABLED) {
        try {
            const ageDays = await getDomainAge(domain);
            if (ageDays !== null) {
                if (ageDays < 30) {
                    score -= 10;
                    reasons.push(`WHOIS: Domain is ${ageDays} days old (< 30 days) (-10)`);
                } else {
                    reasons.push(`WHOIS: Domain is ${ageDays} days old (OK)`);
                }
            } else {
                reasons.push('WHOIS: Could not determine domain age');
            }
        } catch (e) {
            reasons.push('WHOIS: Lookup failed');
        }
    }

    // Final Safety Clamp
    if (score < 0) score = 0;

    const result = {
        email,
        domain,
        isValidSyntax: true,
        isDisposable: false,
        hasMx,
        isRole: roleBased,
        isGibberish: gibberish,
        smtpValid,
        isCatchAll,
        score,
        reasons
    };

    // Store in cache
    cache.set(email, result);

    // Log & metrics
    recordVerification(result);
    logVerification({ ...result, responseTimeMs: Date.now() - startTime });

    return result;
}

module.exports = { verifyEmail };
