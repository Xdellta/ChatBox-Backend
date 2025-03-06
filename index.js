require('dotenv').config();
const express = require('express');

const app = express();
const protocol = process.env.PROTOCOL || 'http';
const host = process.env.HOST || 'localhost';
const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
    res.send('Server is running!');
});

app.listen(port, () => {
    console.log(`Server is running at ${protocol}://${host}:${port} in ${process.env.NODE_ENV || development} mode`);
});