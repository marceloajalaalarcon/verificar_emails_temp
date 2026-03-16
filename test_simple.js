/**
 * Test Suite for Email Verification API v2.0
 * Run: node test_simple.js
 */

const BASE_URL = 'http://localhost:3000';
const API_KEY = process.env.API_KEY || ''; // Set if API_KEY is configured

function headers() {
    const h = { 'Content-Type': 'application/json' };
    if (API_KEY) h['x-api-key'] = API_KEY;
    return h;
}

async function testSingleVerification() {
    console.log('\n=== TEST: Single Email Verification ===\n');

    const emails = [
        'test@mailinator.com',       // Disposable
        'user@gmail.com',           // Valid (should score high)
        'test@guerrillamail.com',   // Disposable
        'user@outlook.com',        // Valid
        'invalid-email',           // Bad syntax
        'admin@gmail.com',         // Role-based
        'a1b2c3d4e5@gmail.com',    // Gibberish
    ];

    for (const email of emails) {
        console.log(`Testing: ${email}`);
        try {
            const res = await fetch(`${BASE_URL}/verify?email=${email}`, { headers: headers() });
            const data = await res.json();
            console.log(`  Score: ${data.score} | Cached: ${data.cached || false}`);
            console.log(`  Reasons: ${(data.reasons || []).join(', ')}`);
        } catch (err) {
            console.error(`  Error: ${err.message}`);
        }
        await new Promise(r => setTimeout(r, 500));
    }
}

async function testCacheHit() {
    console.log('\n=== TEST: Cache Hit ===\n');

    const email = 'cachetest@gmail.com';

    console.log('1st request (should NOT be cached):');
    try {
        const res1 = await fetch(`${BASE_URL}/verify?email=${email}`, { headers: headers() });
        const data1 = await res1.json();
        console.log(`  Score: ${data1.score} | Cached: ${data1.cached || false}`);
    } catch (err) {
        console.error(`  Error: ${err.message}`);
    }

    await new Promise(r => setTimeout(r, 300));

    console.log('2nd request (should be cached):');
    try {
        const res2 = await fetch(`${BASE_URL}/verify?email=${email}`, { headers: headers() });
        const data2 = await res2.json();
        console.log(`  Score: ${data2.score} | Cached: ${data2.cached || false}`);
        if (data2.cached) {
            console.log('  ✅ Cache HIT confirmed!');
        } else {
            console.log('  ❌ Cache MISS — something is wrong');
        }
    } catch (err) {
        console.error(`  Error: ${err.message}`);
    }
}

async function testBulkVerification() {
    console.log('\n=== TEST: Bulk Verification ===\n');

    const payload = {
        emails: [
            'user@gmail.com',
            'test@mailinator.com',
            'user@outlook.com',
            'invalid-email'
        ]
    };

    try {
        const res = await fetch(`${BASE_URL}/verify/bulk`, {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        console.log(`  Summary: ${JSON.stringify(data.summary)}`);
        for (const r of data.results) {
            console.log(`  ${r.email} → Score: ${r.score}`);
        }
    } catch (err) {
        console.error(`  Error: ${err.message}`);
    }
}

async function testBulkValidation() {
    console.log('\n=== TEST: Bulk Validation Errors ===\n');

    // Empty body
    try {
        const res = await fetch(`${BASE_URL}/verify/bulk`, {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify({})
        });
        const data = await res.json();
        console.log(`  No emails: ${res.status} — ${data.error}`);
    } catch (err) {
        console.error(`  Error: ${err.message}`);
    }

    // Too many emails
    try {
        const tooMany = Array.from({ length: 51 }, (_, i) => `user${i}@test.com`);
        const res = await fetch(`${BASE_URL}/verify/bulk`, {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify({ emails: tooMany })
        });
        const data = await res.json();
        console.log(`  Too many: ${res.status} — ${data.error}`);
    } catch (err) {
        console.error(`  Error: ${err.message}`);
    }
}

async function testMetrics() {
    console.log('\n=== TEST: Metrics Endpoint ===\n');

    try {
        const res = await fetch(`${BASE_URL}/metrics`, { headers: headers() });
        const data = await res.json();
        console.log(`  Total Verifications: ${data.totalVerifications}`);
        console.log(`  Cache Hits: ${data.cacheHits}`);
        console.log(`  Cache Misses: ${data.cacheMisses}`);
        console.log(`  Average Score: ${data.averageScore}`);
        console.log(`  Cache Entries: ${data.cache.entries}`);
    } catch (err) {
        console.error(`  Error: ${err.message}`);
    }
}

async function testAuthRequired() {
    console.log('\n=== TEST: Auth (without key) ===\n');

    // Only test if API_KEY is set
    if (!API_KEY) {
        console.log('  ⏭️  Skipped — API_KEY not configured');
        return;
    }

    try {
        const res = await fetch(`${BASE_URL}/verify?email=test@gmail.com`);
        const data = await res.json();
        if (res.status === 401) {
            console.log('  ✅ Correctly rejected request without API key');
        } else {
            console.log(`  ❌ Expected 401, got ${res.status}`);
        }
    } catch (err) {
        console.error(`  Error: ${err.message}`);
    }
}

async function run() {
    console.log('╔══════════════════════════════════════╗');
    console.log('║  Email Verification API v2.0 Tests   ║');
    console.log('╚══════════════════════════════════════╝');
    console.log(`Target: ${BASE_URL}`);
    console.log(`API Key: ${API_KEY ? 'SET' : 'NOT SET'}`);

    await testAuthRequired();
    await testSingleVerification();
    await testCacheHit();
    await testBulkVerification();
    await testBulkValidation();
    await testMetrics();

    console.log('\n✅ All tests completed!\n');
}

run();
