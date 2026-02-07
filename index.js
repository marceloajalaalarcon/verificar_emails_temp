require('dotenv').config();
const express = require('express');
const cors = require('cors');
const verifyRoutes = require('./routes/verify');
const { updateLists } = require('./utils/fetchLists');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Load lists on startup
updateLists().then(() => {
    console.log('Disposable email lists loaded.');
}).catch(err => {
    console.error('Failed to load lists on startup:', err);
});

// Periodic update (every 24 hours)
setInterval(() => {
    updateLists();
}, 24 * 60 * 60 * 1000);

app.use('/verify', verifyRoutes);

app.get('/', (req, res) => {
    res.send('Disposable Email Verification API is running.');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
