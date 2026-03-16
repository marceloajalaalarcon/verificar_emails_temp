/**
 * Domain Intelligence Module
 * Automatically detects suspicious/disposable domains by checking DNS signals.
 *
 * Checks performed:
 *  - SPF record (v=spf1...)
 *  - DMARC record (_dmarc.domain)
 *  - Website existence (A record)
 *  - Domain age (via WHOIS, if enabled)
 *
 * This eliminates dependency on blocklists for zero-day disposable domains.
 */

const dns = require('dns').promises;
const { getDomainAge, WHOIS_ENABLED } = require('./whois');

// Cache domain intel results (avoid repeated DNS lookups)
const intelCache = new Map();
const INTEL_CACHE_TTL = parseInt(process.env.CACHE_TTL_MS) || 3600000;

/**
 * Check if domain has an SPF record.
 * Legitimate domains configure SPF to authorize mail servers.
 */
async function checkSPF(domain) {
    try {
        const records = await dns.resolveTxt(domain);
        // records is an array of arrays of strings
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
 * Legitimate domains configure DMARC for email authentication.
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
 * Most disposable email domains have NO website.
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
 * Get full domain intelligence report.
 * Runs SPF, DMARC, Website, and optionally WHOIS checks in parallel.
 *
 * @param {string} domain
 * @returns {Promise<{hasSPF: boolean, hasDMARC: boolean, hasWebsite: boolean, domainAgeDays: number|null, suspiciousSignals: number, isLikelyDisposable: boolean}>}
 */
async function getDomainIntelligence(domain) {
    const lower = domain.toLowerCase();

    // Check cache
    const cached = intelCache.get(lower);
    if (cached && Date.now() - cached.timestamp < INTEL_CACHE_TTL) {
        return cached.result;
    }

    // Run all checks in parallel for speed
    const [hasSPF, hasDMARC, hasWebsite, domainAgeDays] = await Promise.all([
        checkSPF(lower),
        checkDMARC(lower),
        checkWebsite(lower),
        WHOIS_ENABLED ? getDomainAge(lower).catch(() => null) : Promise.resolve(null)
    ]);

    // Count suspicious signals
    let suspiciousSignals = 0;
    if (!hasSPF) suspiciousSignals++;
    if (!hasDMARC) suspiciousSignals++;
    if (!hasWebsite) suspiciousSignals++;
    if (domainAgeDays !== null && domainAgeDays < 90) suspiciousSignals++;

    const result = {
        hasSPF,
        hasDMARC,
        hasWebsite,
        domainAgeDays,
        suspiciousSignals,
        isLikelyDisposable: suspiciousSignals >= 3
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
