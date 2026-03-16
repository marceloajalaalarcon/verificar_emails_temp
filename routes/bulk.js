const express = require('express');
const router = express.Router();
const { verifyEmail } = require('../utils/verifyEmail');
const { recordBulk } = require('../utils/metrics');

const BULK_MAX = parseInt(process.env.BULK_MAX_EMAILS) || 50;
const CONCURRENCY = 5; // Max parallel SMTP checks

/**
 * Process items with limited concurrency
 */
async function processWithConcurrency(items, fn, concurrency) {
    const results = [];
    let index = 0;

    async function worker() {
        while (index < items.length) {
            const i = index++;
            results[i] = await fn(items[i]);
        }
    }

    const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
    await Promise.all(workers);
    return results;
}

// --- Bulk Email Verification ---

router.post('/', async (req, res) => {
    const { emails } = req.body;

    if (!emails || !Array.isArray(emails)) {
        return res.status(400).json({
            error: 'Invalid request body',
            message: 'Provide { "emails": ["email1@example.com", "email2@example.com"] }'
        });
    }

    if (emails.length === 0) {
        return res.status(400).json({
            error: 'Empty list',
            message: 'Provide at least one email to verify'
        });
    }

    if (emails.length > BULK_MAX) {
        return res.status(400).json({
            error: 'Too many emails',
            message: `Maximum ${BULK_MAX} emails per request. You sent ${emails.length}.`
        });
    }

    // Track bulk metrics
    recordBulk(emails.length);

    // Process with limited concurrency
    const results = await processWithConcurrency(
        emails,
        (email) => verifyEmail(email),
        CONCURRENCY
    );

    // Summary stats
    const summary = {
        total: results.length,
        valid: results.filter(r => r.score >= 70).length,
        risky: results.filter(r => r.score >= 40 && r.score < 70).length,
        invalid: results.filter(r => r.score < 40).length
    };

    res.json({
        summary,
        results
    });
});

module.exports = router;
