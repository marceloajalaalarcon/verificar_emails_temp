/**
 * In-Memory Metrics Tracker
 * Tracks verification counts, cache hits/misses, score distribution.
 */

const counters = {
    totalVerifications: 0,
    cacheHits: 0,
    cacheMisses: 0,
    bulkRequests: 0,
    totalBulkEmails: 0,
    scoreSum: 0,
    statusCounts: {
        valid: 0,       // score >= 70
        risky: 0,       // score 40-69
        invalid: 0      // score < 40
    },
    startedAt: new Date().toISOString()
};

function recordVerification(result) {
    counters.totalVerifications++;
    counters.scoreSum += result.score;

    if (result.cached) {
        counters.cacheHits++;
    } else {
        counters.cacheMisses++;
    }

    if (result.score >= 70) {
        counters.statusCounts.valid++;
    } else if (result.score >= 40) {
        counters.statusCounts.risky++;
    } else {
        counters.statusCounts.invalid++;
    }
}

function recordBulk(emailCount) {
    counters.bulkRequests++;
    counters.totalBulkEmails += emailCount;
}

function getMetrics() {
    const avgScore = counters.totalVerifications > 0
        ? Math.round(counters.scoreSum / counters.totalVerifications)
        : 0;

    return {
        ...counters,
        averageScore: avgScore,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage().rss
    };
}

module.exports = { recordVerification, recordBulk, getMetrics };
