/**
 * WHOIS Domain Age Checker
 * Penalizes very new domains (< 30 days old).
 * Disabled by default via WHOIS_ENABLED=false
 */

const WHOIS_ENABLED = process.env.WHOIS_ENABLED === 'true';

// Simple in-memory WHOIS cache (avoid repeated lookups)
const whoisCache = new Map();
const WHOIS_CACHE_TTL = parseInt(process.env.CACHE_TTL_MS) || 3600000;

async function getDomainAge(domain) {
    if (!WHOIS_ENABLED) return null;

    // Check WHOIS cache
    const cached = whoisCache.get(domain);
    if (cached && Date.now() - cached.timestamp < WHOIS_CACHE_TTL) {
        return cached.ageDays;
    }

    try {
        const whois = require('whois-json');
        const result = await whois(domain, { timeout: 5000 });

        let creationDate = null;

        if (result) {
            // whois-json may return array or object
            const data = Array.isArray(result) ? result[0] : result;
            creationDate = data.creationDate || data.createdDate || data.registrationDate || null;
        }

        if (!creationDate) {
            whoisCache.set(domain, { ageDays: null, timestamp: Date.now() });
            return null;
        }

        const created = new Date(creationDate);
        const ageDays = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));

        whoisCache.set(domain, { ageDays, timestamp: Date.now() });
        return ageDays;
    } catch (err) {
        console.error(`[WHOIS] Error looking up ${domain}:`, err.message);
        whoisCache.set(domain, { ageDays: null, timestamp: Date.now() });
        return null;
    }
}

module.exports = { getDomainAge, WHOIS_ENABLED };
