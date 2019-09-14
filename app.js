const express = require('express');
const mongoose = require('mongoose');
const environment = require('./environment');

const app = express();

// Middleware
app.use(require('./middleware/logger'));
app.use(require('./middleware/body-parser'));
app.use(require('./middleware/urlencoded'));
app.use(require('./middleware/cookie-parser'));
app.use(require('./middleware/cors'));
app.use(require('./middleware/devices'));

// Application Routes
app.use('/', require('./routes/auth'));

// catch 404 and forward to error handler
app.use(require('./routes/error').errorCatcher);

// error handler
app.use(require('./routes/error').errorHandler);

// Database
mongoose.connect(environment.mongo.auth.connectionString, {useNewUrlParser: true, useUnifiedTopology: true})
    .then(() => console.log(`AUTH: MongoDB connected ...`))
    .catch(err => console.error(err));

module.exports = app;
