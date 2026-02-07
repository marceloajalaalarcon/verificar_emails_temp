const express = require('express');
const router = express.Router();
const { isDisposable } = require('../utils/fetchLists');
const dns = require('dns').promises;
const net = require('net');

// --- Heuristics ---

const ROLE_EMAILS = new Set([
    'admin', 'support', 'info', 'contact', 'sales', 'marketing', 'help',
    'webmaster', 'postmaster', 'hostmaster', 'abuse', 'noreply', 'no-reply'
]);

function isRoleBased(user) {
    return ROLE_EMAILS.has(user.toLowerCase());
}

function isGibberish(user) {
    // Basic heuristic: too many numbers or random-looking patterns
    // Example: "a1b2c3d4" -> 8 chars, 50% numbers.
    const digits = user.replace(/[^0-9]/g, '').length;
    const length = user.length;

    // Pattern 1: High digit ratio (> 40%) for users > 6 chars
    if (length > 6 && (digits / length) > 0.4) return true;

    // Pattern 2: Very suspect "temp" patterns (e.g. 10 chars, mixed case handled by lowercase)
    // This is subjective, let's stick to digit ratio for now to avoid false positives.
    return false;
}

// --- Deep Check (SMTP) ---

async function checkSmtp(domain, email) {
    return new Promise(async (resolve) => {
        let mxRecords;
        try {
            mxRecords = await dns.resolveMx(domain);
            if (!mxRecords || mxRecords.length === 0) return resolve(false);
        } catch (e) {
            return resolve(false);
        }

        // Sort by priority (lowest first)
        const mxHost = mxRecords.sort((a, b) => a.priority - b.priority)[0].exchange;

        const socket = net.createConnection(25, mxHost);
        let step = 0;
        let valid = false;

        socket.setTimeout(4000); // 4s timeout

        socket.on('data', (data) => {
            const response = data.toString();
            // console.log(`[SMTP ${mxHost}] ${response.trim()}`);

            if (response.startsWith('220') && step === 0) {
                socket.write(`HELO ${domain}\r\n`);
                step++;
            } else if (response.startsWith('250') && step === 1) {
                socket.write(`MAIL FROM:<check@${domain}>\r\n`); // Pseudo-sender
                step++;
            } else if (response.startsWith('250') && step === 2) {
                socket.write(`RCPT TO:<${email}>\r\n`);
                step++;
            } else if ((response.startsWith('250') || response.startsWith('251')) && step === 3) {
                valid = true;
                socket.end();
            } else {
                // Any other code (5xx, 4xx) means rejected or error
                socket.end();
            }
        });

        socket.on('error', () => resolve(false));
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.on('end', () => resolve(valid));
    });
}


// --- Main Route ---

router.get('/', async (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).json({ error: 'Email parameter is required' });
    }

    // 1. Syntax Check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.json({
            email,
            isValidSyntax: false,
            score: 0,
            reasons: ['Invalid email syntax']
        });
    }

    const [user, domain] = email.split('@');

    // 2. PHASE 1: Blocklist Check (The "Kill Switch")
    const disposable = isDisposable(domain);
    if (disposable) {
        return res.json({
            email,
            domain,
            isValidSyntax: true,
            isDisposable: true,
            score: 0,
            reasons: ['Blocked by Disposable List (Phase 1)']
        });
    }

    // 3. PHASE 2: Deep Verification
    let score = 0;
    let reasons = [];

    // Baseline: Syntax passed (+10)
    score += 10;
    reasons.push('Valid Syntax (+10)');

    // Not in Blocklist (+30) - Implicit since we passed Phase 1
    score += 30;
    reasons.push('Domain Trusted (Not in Blocklist) (+30)');

    // MX Check
    let hasMx = false;
    try {
        const records = await dns.resolveMx(domain);
        hasMx = records && records.length > 0;
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
        // Test 1: Check if the specific user exists
        smtpValid = await checkSmtp(domain, email);

        // Test 2: Check for Catch-All (Zero-Day Disposable Detection)
        // If the user exists, we must verify if the domain accepts EVERYTHING.
        if (smtpValid) {
            const randomUser = 'rx' + Math.random().toString(36).substring(7);
            const randomEmail = `${randomUser}@${domain}`;
            const catchAllValid = await checkSmtp(domain, randomEmail);

            if (catchAllValid) {
                isCatchAll = true;
            }
        }
    }

    if (smtpValid) {
        if (isCatchAll) {
            score -= 40; // Penalty for Catch-All (likely disposable)
            reasons.push('CRITICAL: Domain is Catch-All (Accepts random users) (-40)');
            reasons.push('SMTP Handshake: Mailbox technically exists, but so does everyone else (+0)');
        } else {
            score += 30;
            reasons.push('SMTP Handshake: Mailbox Exists (+30)');
        }
    } else {
        // If SMTP check fails (timeout or rejected), we don't give the points.
        reasons.push('SMTP Handshake: Mailbox not verified or connection failed (+0)');
    }

    // Final Safety Clamp
    if (score < 0) score = 0;

    res.json({
        email,
        domain,
        isValidSyntax: true,
        isDisposable: false,
        hasMx: hasMx,
        isRole: roleBased,
        isGibberish: gibberish,
        smtpValid: smtpValid,
        isCatchAll: isCatchAll,
        score,
        reasons
    });
});

module.exports = router;
