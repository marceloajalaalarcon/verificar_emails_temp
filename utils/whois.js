/**
 * WHOIS Domain Age Checker + Privacy Detection
 * Penalizes very new domains (< 30 days old).
 * Detects WHOIS privacy protection (common in temp mail domains).
 * Disabled by default via WHOIS_ENABLED=false
 */

const WHOIS_ENABLED = process.env.WHOIS_ENABLED === 'true';

// Simple in-memory WHOIS cache (avoid repeated lookups)
const whoisCache = new Map();
const WHOIS_CACHE_TTL = parseInt(process.env.CACHE_TTL_MS) || 3600000;

// Keywords that indicate WHOIS privacy protection
const PRIVACY_KEYWORDS = [
    'privacy', 'redacted', 'withheld', 'protected', 'private',
    'data protected', 'whoisguard', 'domains by proxy',
    'contact privacy', 'identity protect', 'perfect privacy',
    'confidential', 'not disclosed', 'gdpr',
];

/**
 * Internal: get raw WHOIS data (cached).
 */
async function getRawWhois(domain) {
    const cached = whoisCache.get(domain);
    if (cached && Date.now() - cached.timestamp < WHOIS_CACHE_TTL) {
        return cached;
    }

    try {
        const whois = require('whois-json');
        const result = await whois(domain, { timeout: 5000 });

        let creationDate = null;
        let registrant = null;
        let isPrivacy = false;

        if (result) {
            const data = Array.isArray(result) ? result[0] : result;
            creationDate = data.creationDate || data.createdDate || data.registrationDate || null;
            registrant = data.registrantOrganization || data.registrantName || data.registrant || null;

            // Check for privacy protection in registrant fields
            const fieldsToCheck = [
                data.registrantOrganization,
                data.registrantName,
                data.registrant,
                data.adminName,
                data.adminOrganization,
                data.techName,
                data.techOrganization,
            ].filter(Boolean).map(f => f.toLowerCase());

            isPrivacy = fieldsToCheck.some(field =>
                PRIVACY_KEYWORDS.some(kw => field.includes(kw))
            );
        }

        let ageDays = null;
        if (creationDate) {
            const created = new Date(creationDate);
            ageDays = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
        }

        const entry = { ageDays, isPrivacy, registrant, timestamp: Date.now() };
        whoisCache.set(domain, entry);
        return entry;
    } catch (err) {
        console.error(`[WHOIS] Error looking up ${domain}:`, err.message);
        const entry = { ageDays: null, isPrivacy: null, registrant: null, timestamp: Date.now() };
        whoisCache.set(domain, entry);
        return entry;
    }
}

async function getDomainAge(domain) {
    if (!WHOIS_ENABLED) return null;
    const data = await getRawWhois(domain);
    return data.ageDays;
}

/**
 * Detect if domain uses WHOIS privacy protection.
 * Returns true if privacy detected, false if not, null if WHOIS disabled or lookup failed.
 */
async function getWhoisPrivacy(domain) {
    if (!WHOIS_ENABLED) return null;
    const data = await getRawWhois(domain);
    return data.isPrivacy;
}

module.exports = { getDomainAge, getWhoisPrivacy, WHOIS_ENABLED };
