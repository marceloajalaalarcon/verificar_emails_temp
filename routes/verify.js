const express = require('express');
const router = express.Router();
const { verifyEmail } = require('../utils/verifyEmail');

// --- Single Email Verification ---

router.get('/', async (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).json({ error: 'Email parameter is required' });
    }

    const result = await verifyEmail(email);
    res.json(result);
});

module.exports = router;
