const express = require('express');
const router = express.Router();
const { isDisposable } = require('../utils/fetchLists');
const dns = require('dns').promises;

// Helper to check MX records
async function checkMxRecords(domain) {
    try {
        const records = await dns.resolveMx(domain);
        return records && records.length > 0;
    } catch (error) {
        return false;
    }
}

router.get('/', async (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).json({ error: 'Email parameter is required' });
    }

    // Basic syntax validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.json({
            email,
            isValidSyntax: false,
            isDisposable: false,
            hasMxRecords: false,
            score: 0,
            reason: 'Invalid email syntax'
        });
    }

    const domain = email.split('@')[1];

    // Check if disposable
    const disposable = isDisposable(domain);

    // Check MX records
    const hasMx = await checkMxRecords(domain);

    // Scoring Logic
    let score = 0;
    let reasons = [];

    if (disposable) {
        score = 0;
        reasons.push('Domain is in disposable email blocklist');
    } else if (!hasMx) {
        score = 0;
        reasons.push('Domain has no valid MX records');
    } else {
        score = 100;
        reasons.push('Domain is valid and has MX records');
    }

    res.json({
        email,
        domain,
        isValidSyntax: true,
        isDisposable: disposable,
        hasMxRecords: hasMx,
        score,
        reasons
    });
});

module.exports = router;
