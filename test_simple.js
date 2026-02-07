async function test() {
    const emails = [
        'test@mailinator.com',
        'user@gmail.com',
        'test@guerrillamail.com',
        'user@outlook.com',
        'invalid-email',
    ];
    const baseUrl = 'http://localhost:3000/verify';

    for (const email of emails) {
        console.log(`\nTesting: ${email}`);
        try {
            const res = await fetch(`${baseUrl}?email=${email}`);
            const data = await res.json();
            console.log(JSON.stringify(data, null, 2));
        } catch (err) {
            console.error('Error:', err.message);
        }
        await new Promise(r => setTimeout(r, 500)); // Delay
    }
}

test();
