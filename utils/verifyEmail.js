/**
 * Core Email Verification Logic v3.1
 *
 * Changes from v2.1:
 *  - Domain Intel now uses effectiveHas* (with parent domain fallback)
 *  - SMTP contextual scoring uses effective signals
 *  - Catch-all on domain sem website: hard penalty
 *  - WHOIS privacy added as nuclear signal
 *  - SMTP valid + no website + gibberish = clamped to 30
 *  - Corporate domains (Website+SPF) get proper bônus even when SMTP fails
 *  - Nuclear clamp: 4+ signals → max 5, 3+ signals → max 15
 *  - New signal: MX-only domain (has MX, no website, no SPF, no DMARC)
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

function hasConsonantCluster(str, minCluster = 4) {
    const parts = str.toLowerCase().replace(/[aeiou]/g, ' ').split(' ');
    return parts.some(c => c.length >= minCluster);
}

function isGibberish(user) {
    const lower = user.toLowerCase();
    const digits = lower.replace(/[^0-9]/g, '').length;
    const length = lower.length;

    if (length > 6 && (digits / length) >= 0.4) return true;

    const alphaOnly = lower.replace(/[^a-z]/g, '');
    if (alphaOnly.length >= 6) {
        const entropy = shannonEntropy(alphaOnly);
        if (entropy > 3.2) return true;
    }

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
            status: 'undeliverable',
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
            status: 'undeliverable',
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

    // ============================
    // CAMADA 2: SMTP CONTEXTUAL
    // ============================
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

    // ============================
    // CAMADA 2.5: DOMAIN INTEL
    // ============================
    let domainIntel = null;
    const majorProvider = isMajorProvider(domain);

    if (!majorProvider) {
        domainIntel = await getDomainIntelligence(domain);
    }

    // Use EFFECTIVE signals (with parent domain fallback)
    const effWebsite = majorProvider || (domainIntel?.effectiveHasWebsite ?? false);
    const effSPF = majorProvider || (domainIntel?.effectiveHasSPF ?? false);
    const effDMARC = majorProvider || (domainIntel?.effectiveHasDMARC ?? false);

    // ============================
    // CAMADA 3: SMTP SCORING (CONTEXTUAL)
    // ============================
    if (smtpValid && !isCatchAll) {
        if (majorProvider || effWebsite) {
            score += 30;
            reasons.push('SMTP: Mailbox confirmed on established domain (+30)');
        } else {
            // Domain has NO website, even with parent fallback
            // SMTP valid but untrustworthy domain = reduced bonus
            score += 10;
            reasons.push('SMTP: Mailbox exists but domain has NO web presence (+10)');
        }
    } else if (smtpValid && isCatchAll) {
        // Catch-all: zero bonus, will be penalized in combos below
        score += 0;
        reasons.push('SMTP: Catch-all domain, mailbox not individually confirmed (+0)');
    } else {
        // SMTP failed
        if (majorProvider) {
            score += 0;
            reasons.push('SMTP: Blocked by provider (normal for Gmail/Outlook) (+0)');
        } else if (effSPF && effDMARC) {
            // ✅ ALTERADO: SPF+DMARC é suficiente para confiar que a falha do SMTP é apenas um firewall
            // Domínio com autenticação de e-mail configurada corretamente = servidor de e-mail legítimo
            // (não precisa de site — muitas pequenas empresas têm e-mail sem um site)
            score += 0;
            reasons.push('SMTP: Blocked but email auth is solid (SPF+DMARC) (+0)');
        } else if (effWebsite && effSPF) {
            // Corporate domain with proper infrastructure but SMTP blocked
            score += 0;
            reasons.push('SMTP: Blocked but DNS is solid (corporate firewall?) (+0)');
        } else {
            score -= 10;
            reasons.push('SMTP: Failed on unknown/weak domain (-10)');
        }
    }

    // ============================
    // CAMADA 4: DOMAIN INTEL COMBOS
    // ============================
    if (domainIntel && !majorProvider) {

        // --- Bônus para domínios estabelecidos ---
        if (effWebsite && effSPF) {
            score += 10;
            reasons.push('Established domain: Website + SPF (+10)');
        }
        if (effWebsite && effSPF && effDMARC) {
            score += 5;
            reasons.push('Full email infrastructure: SPF + DMARC + Website (+5)');
        }

        // --- Parent domain fallback info ---
        if (domainIntel.usedParentFallback) {
            reasons.push(`Parent domain fallback: ${domainIntel.parentDomain} provided signals`);
        }

        // --- Penalidades por combo ---
        if (!effWebsite && gibberish) {
            score -= 10;
            reasons.push('No website + generated username (-10)');
        }

        if (isCatchAll && !effWebsite) {
            score -= 25;
            reasons.push('Catch-all + no website = likely disposable (-25)');
        }

        if (isCatchAll && gibberish) {
            score -= 15;
            reasons.push('Catch-all + generated username (-15)');
        }

        if (domainIntel.hasSuspiciousName) {
            score -= 15;
            reasons.push('Domain name contains disposable email keywords (-15)');
        }

        if (!effWebsite && !effSPF && !effDMARC) {
            score -= 10;
            reasons.push('No email infrastructure at all (-10)');
        }

        // NEW: SMTP valid on domain with no website = suspicious
        // (temp mail services configure MX+SPF but no website)
        if (smtpValid && !effWebsite && !isCatchAll) {
            score -= 10;
            reasons.push('SMTP valid on domain without website (-10)');
        }

        // NEW: WHOIS privacy on domain without website = suspicious
        if (domainIntel.hasWhoisPrivacy && !effWebsite) {
            score -= 10;
            reasons.push('WHOIS privacy + no website (-10)');
        }

        // ============================
        // NUCLEAR CLAMP
        // ============================
        let suspiciousCount = 0;
        if (!effWebsite) suspiciousCount++;
        if (isCatchAll) suspiciousCount++;
        if (gibberish) suspiciousCount++;
        if (domainIntel.hasSuspiciousName) suspiciousCount++;
        if (!effSPF) suspiciousCount++;
        if (!effDMARC) suspiciousCount++;
        if (domainIntel.hasWhoisPrivacy) suspiciousCount++;
        if (domainIntel.domainAgeDays !== null && domainIntel.domainAgeDays < 90) {
            suspiciousCount++;
        }
        // NEW: SMTP valid + no website counts as signal
        // (temp mails have working SMTP but no website)
        if (smtpValid && !effWebsite) {
            suspiciousCount++;
        }

        if (suspiciousCount >= 5) {
            score = Math.min(score, 5);
            reasons.push(`NUCLEAR: ${suspiciousCount}/9 suspicious signals (clamped to 5)`);
        } else if (suspiciousCount >= 4) {
            score = Math.min(score, 10);
            reasons.push(`CRITICAL: ${suspiciousCount}/9 suspicious signals (clamped to 10)`);
        } else if (suspiciousCount >= 3) {
            score = Math.min(score, 20);
            reasons.push(`WARNING: ${suspiciousCount}/9 suspicious signals (clamped to 20)`);
        }
    }

    // SMTP fail + gibberish combo (independente de domainIntel)
    if (!smtpValid && !majorProvider && gibberish) {
        score -= 5;
        reasons.push('Gibberish user + SMTP fail (-5)');
    }

    // Final Safety Clamp
    if (score < 0) score = 0;

    const status = score >= 70 ? 'deliverable'
        : score >= 40 ? 'risky'
            : 'undeliverable';

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
        status,
        reasons
    };

    cache.set(email, result);
    recordVerification(result);
    logVerification({ ...result, responseTimeMs: Date.now() - startTime });

    return result;
}

module.exports = { verifyEmail };
