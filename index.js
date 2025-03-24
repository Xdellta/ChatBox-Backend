require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
const routes = require('./src/routes/index')
const errorHandler = require('./src/middlewares/errorMiddleware');

const protocol = process.env.PROTOCOL || 'http';
const host = process.env.HOST || 'localhost';
const port = process.env.PORT || 3000;
const clientUrl = process.env.CLIENT_URL || console.error('Incorrect environment configuration. No CLIENT_URL provided.');


app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: clientUrl,
    credentials: true,
  })
);

app.use('/api', routes);
app.use(errorHandler);

app.listen(port, () => {
    console.log(`Server is running at ${protocol}://${host}:${port} in ${process.env.NODE_ENV || 'development'} mode`);
});