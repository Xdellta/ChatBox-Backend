require('dotenv').config();
const express = require('express');
const app = express();
const routes = require('./src/routes/index')
const errorHandler = require('./src/middlewares/errorHandler');

const protocol = process.env.PROTOCOL || 'http';
const host = process.env.HOST || 'localhost';
const port = process.env.PORT || 3000;

app.use(express.json());
app.use('/api', routes);
app.use(errorHandler);

app.listen(port, () => {
    console.log(`Server is running at ${protocol}://${host}:${port} in ${process.env.NODE_ENV || 'development'} mode`);
});