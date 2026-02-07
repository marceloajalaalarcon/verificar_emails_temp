const axios = require('axios');
const customBlocklist = require('./custom_blocklist');

const LIST_URLS = [
    'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
    'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json',
    'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt'
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

    // 1. Add Remote Lists
    for (const url of LIST_URLS) {
        const domains = await fetchList(url);
        domains.forEach(domain => allDomains.add(domain.toLowerCase()));
    }

    // 2. Add Custom Blocklist (Manual Overrides)
    customBlocklist.forEach(domain => allDomains.add(domain.toLowerCase()));

    disposableDomains = allDomains;
    console.log(`Updated lists. Total disposable domains: ${disposableDomains.size} (including ${customBlocklist.length} custom)`);
}

function isDisposable(domain) {
    return disposableDomains.has(domain.toLowerCase());
}

module.exports = { updateLists, isDisposable };
