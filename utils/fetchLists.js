const axios = require('axios');
const customBlocklist = require('./custom_blocklist');

const LIST_URLS = [
    // Atualizadas frequentemente (Padrão Ouro do Github)
    'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf',
    'https://disposable.github.io/disposable-email-domains/domains.txt',
    'https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains_strict.txt',
    'https://raw.githubusercontent.com/amieiro/disposable-email-domains/master/denyDomains.json',
    
    // Listas conhecidas que já usávamos
    'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json',
    'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt',
    'https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt',
    
    // Aggregators & Listas Grandes
    'https://raw.githubusercontent.com/sajjadh47/disposable-email-domains-list/main/domains.txt',
    'https://raw.githubusercontent.com/WebSnifferHQ/disposable-email-domains/main/disposable-email-domains.txt',
    'https://raw.githubusercontent.com/unkn0w/disposable-email-domain-list/master/domains.txt'
];

let disposableDomains = new Set();
let wildcards = new Set(); // For domains like *.027168.com

async function fetchList(url) {
    try {
        const response = await axios.get(url);
        if (typeof response.data === 'string') {
            return response.data.split('\n').map(d => d.trim()).filter(d => d && !d.startsWith('#'));
        } else if (Array.isArray(response.data)) {
            return response.data;
        }
        return [];
    } catch (error) {
        console.error(`Error fetching list from ${url}:`, error.message);
        return [];
    }
}

async function updateLists() {
    console.log('Updating disposable email lists...');
    const allDomains = new Set();
    const allWildcards = new Set();

    // 1. Add Remote Lists
    for (const url of LIST_URLS) {
        const domains = await fetchList(url);
        for (const raw of domains) {
            const domain = raw.toLowerCase();
            // Detect wildcard entries: *.example.com or .example.com
            if (domain.startsWith('*.')) {
                allWildcards.add(domain.slice(2)); // store "example.com"
            } else if (domain.startsWith('.')) {
                allWildcards.add(domain.slice(1)); // store "example.com"
            } else {
                allDomains.add(domain);
            }
        }
    }

    // 2. Add Custom Blocklist (Manual Overrides)
    for (const raw of customBlocklist) {
        const domain = raw.toLowerCase();
        if (domain.startsWith('*.')) {
            allWildcards.add(domain.slice(2));
        } else if (domain.startsWith('.')) {
            allWildcards.add(domain.slice(1));
        } else {
            allDomains.add(domain);
        }
    }

    disposableDomains = allDomains;
    wildcards = allWildcards;
    console.log(`Updated lists. Total disposable domains: ${disposableDomains.size} (including ${customBlocklist.length} custom), Wildcards: ${wildcards.size}`);
}

/**
 * Checks if a domain matches any wildcard pattern.
 * e.g. if wildcards has "027168.com", then "sub.027168.com" matches.
 */
function isWildcardBlocked(domain) {
    const lower = domain.toLowerCase();
    for (const wc of wildcards) {
        if (lower === wc || lower.endsWith('.' + wc)) {
            return true;
        }
    }
    return false;
}

function isDisposable(domain) {
    const lower = domain.toLowerCase();
    return disposableDomains.has(lower) || isWildcardBlocked(lower);
}

/**
 * Inject additional domains into the live disposable set.
 * Used by tempMailScraper to add discovered domains at runtime.
 * @param {Set<string>} domains
 */
function addDomains(domains) {
    let added = 0;
    for (const domain of domains) {
        const lower = domain.toLowerCase();
        if (!disposableDomains.has(lower)) {
            disposableDomains.add(lower);
            added++;
        }
    }
    if (added > 0) {
        console.log(`[fetchLists] Injected ${added} scraped domains into live blocklist (total: ${disposableDomains.size})`);
    }
}

module.exports = { updateLists, isDisposable, isWildcardBlocked, addDomains };

