const cookieParser = require('cookie-parser');
const config = require('../config');

module.exports = cookieParser(config.COOKIE.SECRET);
