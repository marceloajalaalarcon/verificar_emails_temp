const axios = require('axios');
const customBlocklist = require('./custom_blocklist');

const LIST_URLS = [
    'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
    'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json',
    'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt',
    'https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt'
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

module.exports = { updateLists, isDisposable, isWildcardBlocked };
