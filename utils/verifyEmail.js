/**
 * Core Email Verification Logic v2.1
 *
 * Changes from v2.0:
 *  - Improved isGibberish() with Shannon entropy + consonant cluster detection
 *  - MAJOR_PROVIDERS set: Gmail/Outlook/etc. not penalized for SMTP fail
 *  - SMTP fail penalty for unknown domains (-10, combo -5)
 *  - Domain Intelligence: automatic zero-day detection via SPF/DMARC/Website/Age
 *  - Nuclear penalty when 3+ suspicious signals detected
 */

const dns = require('dns').promises;
const net = require('net');
const { isDisposable } = require('./fetchLists');
const cache = require('./cache');
const { logVerification } = require('./logger');
const { recordVerification } = require('./metrics');
const { getDomainAge, WHOIS_ENABLED } = require('./whois');
const { getDomainIntelligence } = require('./domainIntel');

// --- Config from .env ---
const SMTP_TIMEOUT = parseInt(process.env.SMTP_TIMEOUT_MS) || 4000;
const GREYLISTING_RETRY = process.env.GREYLISTING_RETRY !== 'false';
const GREYLISTING_DELAY = parseInt(process.env.GREYLISTING_DELAY_MS) || 3000;

// --- Heuristics ---

const ROLE_EMAILS = new Set([
    'admin', 'support', 'info', 'contact', 'sales', 'marketing', 'help',
    'webmaster', 'postmaster', 'hostmaster', 'abuse', 'noreply', 'no-reply'
]);

// Major email providers that legitimately block SMTP probing
const MAJOR_PROVIDERS = new Set([
    'gmail.com', 'googlemail.com',
    'yahoo.com', 'yahoo.com.br', 'ymail.com',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'outlook.com.br', 'hotmail.com.br',
    'aol.com',
    'icloud.com', 'me.com', 'mac.com',
    'protonmail.com', 'proton.me', 'pm.me',
    'zoho.com',
    'mail.ru', 'yandex.com', 'yandex.ru',
    'gmx.com', 'gmx.net',
    'fastmail.com',
    'tutanota.com', 'tuta.io',
    'uol.com.br', 'bol.com.br', 'terra.com.br', 'globo.com',
]);

function isRoleBased(user) {
    return ROLE_EMAILS.has(user.toLowerCase());
}

function isMajorProvider(domain) {
    return MAJOR_PROVIDERS.has(domain.toLowerCase());
}

// --- Improved Gibberish Detection ---

/**
 * Shannon entropy — measures randomness of a string.
 * Real names: higher per-character variety in predictable patterns.
 * Generated strings: uniform distribution → specific entropy range.
 */
function shannonEntropy(str) {
    if (str.length === 0) return 0;
    const freq = {};
    for (const ch of str) {
        freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
        const p = freq[ch] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/**
 * Detects clusters of 4+ consecutive consonants.
 * Common in machine-generated strings, rare in real names.
 */
function hasConsonantCluster(str, minCluster = 4) {
    const parts = str.toLowerCase().replace(/[aeiou]/g, ' ').split(' ');
    return parts.some(c => c.length >= minCluster);
}

function isGibberish(user) {
    const lower = user.toLowerCase();
    const digits = lower.replace(/[^0-9]/g, '').length;
    const length = lower.length;

    // Pattern 1: High digit ratio (>= 40%) for users > 6 chars
    // Fixes: jimaci8303 → 4/10 = 0.4 → now detected (was > 0.4, now >= 0.4)
    if (length > 6 && (digits / length) >= 0.4) return true;

    // Pattern 2: Shannon entropy on alpha-only portion
    // Real names usually have lower entropy (repeated vowels/consonants like 'contato', 'maria')
    // Random strings without repeated characters have higher entropy.
    // Max entropy for length N is log2(N). 
    const alphaOnly = lower.replace(/[^a-z]/g, '');
    if (alphaOnly.length >= 6) {
        const entropy = shannonEntropy(alphaOnly);
        // If string is perfectly uniform (e.g. 6 different lowercase letters = 2.58 entropy)
        // We only flag extremely high entropy strings (e.g., 8+ random unique chars)
        if (entropy > 3.2) return true;
    }

    // Pattern 3: Consonant clusters (4+ consecutive consonants)
    if (hasConsonantCluster(lower.replace(/[^a-z]/g, ''))) return true;

    return false;
}

// --- SMTP Check ---

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
                    const randomUser = 'rx' + Math.random().toString(36).substring(7);
                    socket.write(`RCPT TO:<${randomUser}@${domain}>\r\n`);
                    step++;
                } else {
                    socket.write('QUIT\r\n');
                    step = 99;
                }
            } else if ((response.startsWith('250') || response.startsWith('251')) && step === 4) {
                isCatchAll = true;
                socket.write('QUIT\r\n');
                step = 99;
            } else if (response.startsWith('4') && step === 3) {
                greylisted = true;
                socket.write('QUIT\r\n');
                step = 99;
            } else if (step === 4) {
                socket.write('QUIT\r\n');
                step = 99;
            } else if (step === 99) {
                // After QUIT, ignore
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

    // 0. Cache
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

    score += 10;
    reasons.push('Valid Syntax (+10)');

    score += 30;
    reasons.push('Domain Trusted (Not in Blocklist) (+30)');

    // MX Check
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

    // SMTP Deep Check
    let smtpValid = false;
    let isCatchAll = false;

    if (hasMx) {
        const mxHost = mxRecords.sort((a, b) => a.priority - b.priority)[0].exchange;
        let smtpResult = await checkSmtp(mxHost, domain, email, { checkCatchAll: true });

        if (smtpResult.greylisted && GREYLISTING_RETRY) {
            reasons.push(`Greylisting detected, retrying after ${GREYLISTING_DELAY}ms...`);
            await sleep(GREYLISTING_DELAY);
            smtpResult = await checkSmtp(mxHost, domain, email, { checkCatchAll: true });
        }

        smtpValid = smtpResult.smtpValid;
        isCatchAll = smtpResult.isCatchAll;
    }

    // 4. PHASE 2.5: Domain Intelligence (automatic zero-day detection)
    let domainIntel = null;
    if (!isMajorProvider(domain)) {
        domainIntel = await getDomainIntelligence(domain);

        if (!domainIntel.hasSPF) {
            score -= 5;
            reasons.push('Domain Intel: No SPF record found (-5)');
        }
        if (!domainIntel.hasDMARC) {
            score -= 5;
            reasons.push('Domain Intel: No DMARC record found (-5)');
        }
        if (!domainIntel.hasWebsite) {
            score -= 5;
            reasons.push('Domain Intel: No website (A record) found (-5)');
        }
        if (domainIntel.domainAgeDays !== null && domainIntel.domainAgeDays < 90) {
            score -= 10;
            reasons.push(`Domain Intel: Domain is only ${domainIntel.domainAgeDays} days old (-10)`);
        }

        // Nuclear: 3+ suspicious signals = almost certainly disposable
        if (domainIntel.suspiciousSignals >= 3) {
            score -= 15;
            reasons.push(`CRITICAL: Domain has ${domainIntel.suspiciousSignals}/4 suspicious signals — likely disposable (-15)`);
        }
    }

    if (smtpValid) {
        if (isCatchAll) {
            if (!isMajorProvider(domain) && domainIntel && (!domainIntel.hasWebsite || !domainIntel.hasDMARC)) {
                // Catch-All + Unknown Domain + Missing web/DMARC = Highly likely Temp Mail
                score -= 80;
                reasons.push('NUCLEAR: Domain is Catch-All + Suspicious DNS = Likely Temp Mail (-80)');
            } else {
                score -= 40;
                reasons.push('CRITICAL: Domain is Catch-All (Accepts any user) (-40)');
            }
        } else {
            score += 30;
            reasons.push('SMTP Handshake: Mailbox Exists (+30)');
        }
    } else {
        // Penalize SMTP fail on unknown domains
        if (isMajorProvider(domain)) {
            reasons.push('SMTP: Blocked by provider (expected for major providers) (+0)');
        } else if (domainIntel && domainIntel.hasSPF && domainIntel.hasDMARC) {
            // Corporate firewall likely blocked the probe, don't penalize heavily
            score -= 2;
            reasons.push('SMTP: Mailbox not verified, but DNS is solid (corporate firewall?) (-2)');
        } else {
            score -= 10;
            reasons.push('SMTP: Mailbox not verified on unknown/weak domain (-10)');
            if (gibberish) {
                score -= 5;
                reasons.push('SUSPICIOUS COMBO: Gibberish user + unknown domain + SMTP fail (-5)');
            }
        }
    }

    // 5. WHOIS (legacy, only if not already checked by domainIntel)
    if (WHOIS_ENABLED && isMajorProvider(domain)) {
        // domainIntel already handles WHOIS for non-major providers
        // This branch only runs WHOIS for major providers (rarely useful, kept for completeness)
        try {
            const ageDays = await getDomainAge(domain);
            if (ageDays !== null && ageDays < 30) {
                score -= 10;
                reasons.push(`WHOIS: Domain is ${ageDays} days old (< 30 days) (-10)`);
            }
        } catch (e) {
            // Ignore
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
        domainIntel: domainIntel || null,
        score,
        reasons
    };

    cache.set(email, result);
    recordVerification(result);
    logVerification({ ...result, responseTimeMs: Date.now() - startTime });

    return result;
}

module.exports = { verifyEmail };
