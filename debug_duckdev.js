const dns = require('dns').promises;
const net = require('net');

async function checkSmtp(domain, email) {
    console.log(`\n--- Checking ${email} ---`);
    return new Promise(async (resolve) => {
        let mxRecords;
        try {
            mxRecords = await dns.resolveMx(domain);
            console.log('MX Records:', mxRecords);
        } catch (e) {
            console.log('DNS Error:', e.message);
            return resolve(false);
        }

        if (!mxRecords || mxRecords.length === 0) return resolve(false);
        const mxHost = mxRecords.sort((a, b) => a.priority - b.priority)[0].exchange;
        console.log(`MX Host: ${mxHost}`);

        const socket = net.createConnection(25, mxHost);
        let step = 0;

        socket.setTimeout(8000); // Increased timeout

        socket.on('data', (data) => {
            const response = data.toString().trim();
            console.log(`Server: ${response}`);

            if (response.startsWith('220') && step === 0) {
                console.log('Client: HELO ' + domain);
                socket.write(`HELO ${domain}\r\n`);
                step++;
            } else if (response.startsWith('250') && step === 1) {
                console.log('Client: MAIL FROM:<check@' + domain + '>');
                socket.write(`MAIL FROM:<check@${domain}>\r\n`);
                step++;
            } else if (response.startsWith('250') && step === 2) {
                console.log('Client: RCPT TO:<' + email + '>');
                socket.write(`RCPT TO:<${email}>\r\n`);
                step++;
            } else if ((response.startsWith('250') || response.startsWith('251')) && step === 3) {
                console.log('Result: VALID (250/251)');
                socket.end();
            } else {
                console.log('Result: Response code not 250/251, ending.');
                socket.end();
            }
        });

        socket.on('error', (err) => {
            console.log('Socket Error:', err.message);
        });
        socket.on('timeout', () => {
            console.log('Socket Timeout');
            socket.destroy();
        });
    });
}

checkSmtp('duckdev.com.br', 'contato@duckdev.com.br');
