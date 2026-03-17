require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const apiKeyAuth = require('./middleware/auth');
const verifyRoutes = require('./routes/verify');
const bulkRoutes = require('./routes/bulk');
const { updateLists, addDomains } = require('./utils/fetchLists');
const { startScraper } = require('./utils/tempMailScraper');
const { getMetrics } = require('./utils/metrics');
const { stats: cacheStats } = require('./utils/cache');
const { intelCacheStats } = require('./utils/domainIntel');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Global Middleware ---
app.use(cors());
app.use(express.json());

// --- Rate Limiting ---
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.'
    }
});
app.use(limiter);

// --- Load disposable email lists, then start scraper ---
updateLists().then(() => {
    console.log('Disposable email lists loaded.');
    // Start auto-discovery of temp mail domains AFTER lists are loaded
    startScraper(addDomains);
}).catch(err => {
    console.error('Failed to load lists on startup:', err);
});

// Refresh lists every 24 hours
setInterval(() => {
    updateLists();
}, 24 * 60 * 60 * 1000);

// --- Routes ---

// Health check (no auth required)
app.get('/', (req, res) => {
    res.json({
        status: 'running',
        service: 'Email Verification API',
        version: '2.1.0',
        endpoints: {
            verify: 'GET /verify?email=user@example.com',
            bulk: 'POST /verify/bulk { "emails": [...] }',
            metrics: 'GET /metrics'
        }
    });
});

// Protected routes
app.use('/verify', apiKeyAuth, verifyRoutes);
app.use('/verify/bulk', apiKeyAuth, bulkRoutes);

// Metrics endpoint (protected)
app.get('/metrics', apiKeyAuth, (req, res) => {
    res.json({
        ...getMetrics(),
        cache: cacheStats(),
        domainIntelCache: intelCacheStats()
    });
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`API Key: ${process.env.API_KEY ? 'ENABLED' : 'DISABLED (open access)'}`);
    console.log(`Rate Limit: ${parseInt(process.env.RATE_LIMIT_MAX) || 100} requests per ${Math.round((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 60000)} minutes`);
    console.log(`WHOIS: ${process.env.WHOIS_ENABLED === 'true' ? 'ENABLED' : 'DISABLED'}`);
});
