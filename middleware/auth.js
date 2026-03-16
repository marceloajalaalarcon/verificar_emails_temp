/**
 * API Key Authentication Middleware
 * If API_KEY is not set in .env, authentication is disabled (open access).
 */

function apiKeyAuth(req, res, next) {
    const configuredKey = process.env.API_KEY;

    // If no API_KEY configured, skip authentication
    if (!configuredKey) {
        return next();
    }

    const providedKey = req.headers['x-api-key'];

    if (!providedKey) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Provide your API key in the x-api-key header'
        });
    }

    if (providedKey !== configuredKey) {
        return res.status(403).json({
            error: 'Forbidden',
            message: 'Invalid API key'
        });
    }

    next();
}

module.exports = apiKeyAuth;
