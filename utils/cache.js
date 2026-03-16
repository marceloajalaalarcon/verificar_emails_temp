/**
 * In-Memory Cache with TTL
 * Avoids re-verifying the same email within the TTL window.
 */

const CACHE_TTL = parseInt(process.env.CACHE_TTL_MS) || 3600000; // 1 hour default
const CLEANUP_INTERVAL = 10 * 60 * 1000; // 10 minutes

const cache = new Map();

function get(email) {
    const key = email.toLowerCase();
    const entry = cache.get(key);
    if (!entry) return null;

    if (Date.now() - entry.timestamp > CACHE_TTL) {
        cache.delete(key);
        return null;
    }

    return { ...entry.result, cached: true };
}

function set(email, result) {
    const key = email.toLowerCase();
    cache.set(key, {
        result,
        timestamp: Date.now()
    });
}

function has(email) {
    return get(email) !== null;
}

function size() {
    return cache.size;
}

function stats() {
    return {
        entries: cache.size,
        ttlMs: CACHE_TTL
    };
}

// Periodic cleanup of expired entries
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of cache) {
        if (now - entry.timestamp > CACHE_TTL) {
            cache.delete(key);
        }
    }
}, CLEANUP_INTERVAL).unref();

module.exports = { get, set, has, size, stats };
