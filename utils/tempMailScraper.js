/**
 * Temp Mail Domain Auto-Discovery
 * 
 * Periodically scrapes known temporary email service APIs to discover
 * their currently active domains. Newly discovered domains are:
 *  1. Added to the in-memory disposable set immediately
 *  2. Persisted to data/discovered_domains.json for survival across restarts
 *
 * Supported services:
 *  - mail.tm (GET https://api.mail.tm/domains — no auth)
 *  - mail.gw (GET https://api.mail.gw/domains — no auth)  
 *  - 1secmail (GET https://www.1secmail.com/api/v1/?action=getDomainList)
 *  - Internxt (GET https://api.internxt.com/temp-mail/domains)
 *  - GuerrillaMail (hardcoded known domains)
 *  - temp-mail.org (hardcoded known domains)
 *
 * Run interval: configurable via SCRAPER_INTERVAL_MS (default: 1 hour)
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DISCOVERED_FILE = path.join(DATA_DIR, 'discovered_domains.json');
const SCRAPER_INTERVAL = parseInt(process.env.SCRAPER_INTERVAL_MS) || 60 * 60 * 1000; // 1 hour

// Known GuerrillaMail domains (no public API for domains)
const GUERRILLAMAIL_DOMAINS = [
    'guerrillamail.com', 'guerrillamail.de', 'guerrillamail.net',
    'guerrillamail.org', 'guerrillamail.info', 'guerrillamailblock.com',
    'sharklasers.com', 'grr.la', 'guerrillamail.biz',
    'spam4.me', 'pokemail.net'
];

// Known temp-mail.org associated domains (rotates frequently)
const TEMPMAILORG_KNOWN = [
    'mailto.plus', 'fexpost.com', 'fexbox.org', 'fexbox.ru',
    'mailbox.in.ua', 'rover.info', 'inpwa.com', 'intxmail.com',
    'chitthi.in', 'damda.net'
];

/**
 * Fetch domains from an API endpoint.
 * Handles different response formats.
 */
async function fetchFromAPI(name, url, parser) {
    try {
        const response = await axios.get(url, { timeout: 10000 });
        const domains = parser(response.data);
        if (domains.length > 0) {
            console.log(`[Scraper] ${name}: found ${domains.length} domains`);
        }
        return domains;
    } catch (err) {
        // Soft warning. It's common for these APIs to go down or block IPs (403, 404, etc)
        const status = err.response ? err.response.status : 'Network Error';
        console.log(`[Scraper] ⚠️ ${name} indisponível no momento (Status: ${status}). Ignorando...`);
        return [];
    }
}

/**
 * Scrape all known temp mail services for their current domains.
 */
async function scrapeAllServices() {
    const allDomains = new Set();

    // 1. mail.tm — Hydra JSON-LD format
    const mailTm = await fetchFromAPI(
        'mail.tm',
        'https://api.mail.tm/domains',
        (data) => {
            if (data && data['hydra:member']) {
                return data['hydra:member']
                    .filter(d => d.isActive)
                    .map(d => d.domain.toLowerCase());
            }
            return [];
        }
    );
    mailTm.forEach(d => allDomains.add(d));

    // 2. mail.gw — Same format as mail.tm (sister service)
    const mailGw = await fetchFromAPI(
        'mail.gw',
        'https://api.mail.gw/domains',
        (data) => {
            if (data && data['hydra:member']) {
                return data['hydra:member']
                    .filter(d => d.isActive)
                    .map(d => d.domain.toLowerCase());
            }
            return [];
        }
    );
    mailGw.forEach(d => allDomains.add(d));

    // 3. 1secmail — simple JSON array
    const secmail = await fetchFromAPI(
        '1secmail',
        'https://www.1secmail.com/api/v1/?action=getDomainList',
        (data) => {
            if (Array.isArray(data)) {
                return data.map(d => d.toLowerCase());
            }
            return [];
        }
    );
    secmail.forEach(d => allDomains.add(d));

    // 4. Internxt temp mail
    const internxt = await fetchFromAPI(
        'internxt',
        'https://api.internxt.com/temp-mail/domains',
        (data) => {
            if (Array.isArray(data)) {
                return data.map(d => (d.domain || d).toString().toLowerCase());
            }
            return [];
        }
    );
    internxt.forEach(d => allDomains.add(d));

    // 5. Hardcoded known domains (GuerrillaMail, temp-mail.org, etc.)
    GUERRILLAMAIL_DOMAINS.forEach(d => allDomains.add(d));
    TEMPMAILORG_KNOWN.forEach(d => allDomains.add(d));

    return allDomains;
}

/**
 * Load previously discovered domains from file.
 */
function loadDiscoveredDomains() {
    try {
        if (fs.existsSync(DISCOVERED_FILE)) {
            const data = JSON.parse(fs.readFileSync(DISCOVERED_FILE, 'utf8'));
            return new Set(data.domains || []);
        }
    } catch (err) {
        console.error('[Scraper] Failed to load discovered domains:', err.message);
    }
    return new Set();
}

/**
 * Save discovered domains to file for persistence across restarts.
 */
function saveDiscoveredDomains(domains) {
    try {
        if (!fs.existsSync(DATA_DIR)) {
            fs.mkdirSync(DATA_DIR, { recursive: true });
        }
        const data = {
            lastUpdated: new Date().toISOString(),
            count: domains.size,
            domains: [...domains].sort()
        };
        fs.writeFileSync(DISCOVERED_FILE, JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
        console.error('[Scraper] Failed to save discovered domains:', err.message);
    }
}

/**
 * Main scraper function.
 * Discovers domains, merges with previously found ones, persists to disk.
 * Returns a callback (addToBlocklist) that must be called with the fetchLists addDomains function.
 *
 * @param {function} addToBlocklist - function(Set<string>) that adds domains to the live disposable set
 */
async function runScraper(addToBlocklist) {
    console.log('[Scraper] Scanning temp mail services...');

    // Load previously discovered domains
    const previouslyDiscovered = loadDiscoveredDomains();

    // Scrape all services
    const newlyScraped = await scrapeAllServices();

    // Merge
    const allDiscovered = new Set([...previouslyDiscovered, ...newlyScraped]);

    // Find truly new domains (not seen before)
    const brandNew = [];
    for (const domain of newlyScraped) {
        if (!previouslyDiscovered.has(domain)) {
            brandNew.push(domain);
        }
    }

    if (brandNew.length > 0) {
        console.log(`[Scraper] 🆕 Discovered ${brandNew.length} new domains: ${brandNew.join(', ')}`);
    }

    // Save all to disk
    saveDiscoveredDomains(allDiscovered);

    // Add to live blocklist
    if (addToBlocklist) {
        addToBlocklist(allDiscovered);
    }

    console.log(`[Scraper] Total discovered domains: ${allDiscovered.size}`);
    return allDiscovered;
}

/**
 * Start the periodic scraper.
 * @param {function} addToBlocklist - function(Set<string>) to inject domains into live blocklist
 */
function startScraper(addToBlocklist) {
    // Run immediately on startup
    runScraper(addToBlocklist);

    // Then run periodically
    const interval = setInterval(() => {
        runScraper(addToBlocklist);
    }, SCRAPER_INTERVAL);
    interval.unref();

    console.log(`[Scraper] Scheduled to run every ${Math.round(SCRAPER_INTERVAL / 60000)} minutes`);
}

module.exports = { startScraper, runScraper, loadDiscoveredDomains };
