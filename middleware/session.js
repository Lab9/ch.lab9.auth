const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
const mongoose = require('mongoose');
const env = require('../environment');
const connection = mongoose.createConnection(env.mongo.session.connectionString, {useNewUrlParser: true});

module.exports = session({
    secret: env.session.secret,
    resave: env.session.reSave,
    saveUninitialized: env.session.saveUninitialized,
    cookie: {
        secure: env.session.cookie.secure
    },
    store: new MongoStore({mongooseConnection: connection})
});
