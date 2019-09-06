const mongoose = require('mongoose');

const BlackListSchema = mongoose.Schema({
    token: {
        type: String,
        required: true
    },
    userId: {
        type: String,
        required: true
    }
});

module.exports = mongoose.model('Blacklist', BlackListSchema, 'blacklist');
