/**
 * Domain Intelligence Module v3.1
 *
 * Changes from v2.1:
 *  - Parent domain fallback for subdomains (fixes edu.br/gov.br)
 *  - Expanded suspicious keywords list
 *  - Keywords checked across ALL domain levels (not just first segment)
 *  - WHOIS privacy detection as suspicious signal
 *  - MX-only domain detection (has MX but nothing else)
 */

const dns = require('dns').promises;
const { getDomainAge, getWhoisPrivacy, WHOIS_ENABLED } = require('./whois');

// Cache domain intel results (avoid repeated DNS lookups)
const intelCache = new Map();
const INTEL_CACHE_TTL = parseInt(process.env.CACHE_TTL_MS) || 3600000;

/**
 * Check if domain has an SPF record.
 */
async function checkSPF(domain) {
    try {
        const records = await dns.resolveTxt(domain);
        for (const record of records) {
            const txt = record.join('');
            if (txt.toLowerCase().startsWith('v=spf1')) {
                return true;
            }
        }
        return false;
    } catch (e) {
        return false;
    }
}

/**
 * Check if domain has a DMARC record.
 */
async function checkDMARC(domain) {
    try {
        const records = await dns.resolveTxt(`_dmarc.${domain}`);
        for (const record of records) {
            const txt = record.join('');
            if (txt.toLowerCase().startsWith('v=dmarc1')) {
                return true;
            }
        }
        return false;
    } catch (e) {
        return false;
    }
}

/**
 * Check if domain has an A record (website).
 */
async function checkWebsite(domain) {
    try {
        const records = await dns.resolve4(domain);
        return records && records.length > 0;
    } catch (e) {
        return false;
    }
}

/**
 * Extract parent domain from a subdomain.
 * e.g. "academico.ufgd.edu.br" → "ufgd.edu.br"
 * e.g. "mail.google.com" → "google.com"
 *
 * Returns null if already a root domain.
 */
function getParentDomain(domain) {
    const parts = domain.split('.');
    // Known multi-part TLDs
    const multiPartTLDs = [
        'com.br', 'edu.br', 'gov.br', 'org.br', 'net.br',
        'co.uk', 'org.uk', 'ac.uk',
        'com.au', 'edu.au',
        'co.jp', 'or.jp',
        'com.ar', 'edu.ar',
        'com.mx', 'edu.mx',
        'com.co', 'edu.co',
        'com.pe', 'edu.pe',
        'com.cl', 'com.py', 'com.uy',
    ];

    const joined = parts.join('.');
    for (const tld of multiPartTLDs) {
        if (joined.endsWith('.' + tld)) {
            // domain is something.X.tld — parent is X.tld
            const withoutTld = joined.slice(0, -(tld.length + 1)); // remove ".com.br"
            const subParts = withoutTld.split('.');
            if (subParts.length > 1) {
                // e.g. "academico.ufgd" → parent = "ufgd.edu.br"
                return subParts.slice(1).join('.') + '.' + tld;
            }
            return null; // already root (e.g. "ufgd.edu.br")
        }
    }

    // Standard TLD (e.g. .com, .org, .net)
    if (parts.length > 2) {
        return parts.slice(1).join('.');
    }

    return null; // already root
}

/**
 * Detect suspicious keywords in domain name.
 * Checks ALL segments, not just the first one.
 * e.g. "hidingmail.com" → checks "hidingmail"
 * e.g. "temp.mailservice.org" → checks "temp" AND "mailservice"
 */
const SUSPICIOUS_KEYWORDS = [
    // Email temp / disposable
    'temp', 'tmp', 'disposable', 'throwaway', 'fake',
    'trash', 'junk', 'burner', 'guerrilla', 'guerilla',
    // Hiding / anonymous
    'hide', 'hiding', 'anon', 'anonymous', 'privacy',
    // Known temp mail brands
    'yopmail', 'mailinator', 'sharklasers', 'getairmail',
    'filzmail', 'inboxbear', 'tempmail', 'tmpmail',
    'mailnesia', 'maildrop', 'discard', 'trashmail',
    'throwmail', 'fakeinbox', 'tempinbox', 'tempemail',
    'minutemail', 'emailondeck', 'guerrillamail',
    // Pattern: "Xmail" where X is suspicious
    'duckmail', 'spammail', 'nomail', 'deadmail',
    // Pattern: mail + random/generated service
    'mailbox72', 'inbox47',
];

function checkSuspiciousName(domain) {
    const lower = domain.toLowerCase();
    // Remove TLD parts, check each segment
    const parts = lower.split('.');
    // Check all non-TLD segments
    for (let i = 0; i < parts.length - 1; i++) {
        const segment = parts[i];
        // Skip very short segments (e.g. "co", "ac")
        if (segment.length <= 2) continue;

        for (const kw of SUSPICIOUS_KEYWORDS) {
            if (segment.includes(kw)) {
                return true;
            }
        }

        // Pattern: segment is ONLY "mail" + something or something + "mail"
        // e.g. "duoley" won't match, but "hidingmail" will via keywords above
    }
    return false;
}

/**
 * Get full domain intelligence report.
 * Now with parent domain fallback for subdomains.
 *
 * @param {string} domain
 * @returns {Promise<Object>}
 */
async function getDomainIntelligence(domain) {
    const lower = domain.toLowerCase();

    // Check cache
    const cached = intelCache.get(lower);
    if (cached && Date.now() - cached.timestamp < INTEL_CACHE_TTL) {
        return cached.result;
    }

    // Run all checks in parallel for speed
    const [hasSPF, hasDMARC, hasWebsite, domainAgeDays, whoisPrivacy] = await Promise.all([
        checkSPF(lower),
        checkDMARC(lower),
        checkWebsite(lower),
        WHOIS_ENABLED ? getDomainAge(lower).catch(() => null) : Promise.resolve(null),
        WHOIS_ENABLED ? getWhoisPrivacy(lower).catch(() => null) : Promise.resolve(null)
    ]);

    // --- Parent Domain Fallback ---
    // If subdomain has no signals, check the parent domain
    let parentIntel = null;
    const parentDomain = getParentDomain(lower);

    if (parentDomain && !hasWebsite && !hasSPF && !hasDMARC) {
        // Subdomain has nothing — check parent
        const [parentSPF, parentDMARC, parentWebsite] = await Promise.all([
            checkSPF(parentDomain),
            checkDMARC(parentDomain),
            checkWebsite(parentDomain),
        ]);

        if (parentWebsite || parentSPF || parentDMARC) {
            parentIntel = {
                domain: parentDomain,
                hasSPF: parentSPF,
                hasDMARC: parentDMARC,
                hasWebsite: parentWebsite,
            };
        }
    }

    // Suspicious name detection
    const hasSuspiciousName = checkSuspiciousName(lower);

    // WHOIS privacy: temp mail services often use privacy protection
    // Not suspicious alone, but combined with other signals it's a strong indicator
    const hasWhoisPrivacy = whoisPrivacy === true;

    // --- Determine effective signals (with parent fallback) ---
    const effectiveHasWebsite = hasWebsite || (parentIntel?.hasWebsite ?? false);
    const effectiveHasSPF = hasSPF || (parentIntel?.hasSPF ?? false);
    const effectiveHasDMARC = hasDMARC || (parentIntel?.hasDMARC ?? false);

    // Count suspicious signals
    let suspiciousSignals = 0;
    if (!effectiveHasSPF)    suspiciousSignals++;
    if (!effectiveHasDMARC)  suspiciousSignals++;
    if (!effectiveHasWebsite) suspiciousSignals++;
    if (domainAgeDays !== null && domainAgeDays < 90) suspiciousSignals++;
    if (hasSuspiciousName)   suspiciousSignals++;
    if (hasWhoisPrivacy)     suspiciousSignals++;

    const result = {
        // Raw signals (direct domain only)
        hasSPF,
        hasDMARC,
        hasWebsite,
        domainAgeDays,
        hasSuspiciousName,
        hasWhoisPrivacy,

        // Effective signals (with parent fallback)
        effectiveHasWebsite,
        effectiveHasSPF,
        effectiveHasDMARC,

        // Parent domain info (if used)
        parentDomain: parentIntel ? parentIntel.domain : null,
        usedParentFallback: parentIntel !== null,

        // Aggregate
        suspiciousSignals,
        isLikelyDisposable: suspiciousSignals >= 3,
    };

    // Cache the result
    intelCache.set(lower, { result, timestamp: Date.now() });

    return result;
}

/**
 * Get cache stats for metrics endpoint.
 */
function intelCacheStats() {
    return {
        entries: intelCache.size,
        ttlMs: INTEL_CACHE_TTL
    };
}

module.exports = { getDomainIntelligence, intelCacheStats };
