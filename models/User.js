const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    lid: {
        type: String,
        required: true,
        unique: true
    },
    type: {
        type: String,
        required: true,
        enum: ['coa', 'app', 'esc', 'lua'],
        default: 'lua'
    },
    email: {
        type: String,
        required: true,
        max: 255,
        min: 7,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    secret: {
        type: String,
        required: true,
        unique: true
    },
    admin: {
        type: Boolean,
        required: true,
        default: false
    },
    lastLogin: {
        type: Date,
        default: Date.now(),
        required: true
    },
    createdAt: {
        type: Date,
        required: true,
        default: Date.now()
    },
    lastUpdate: {
        type: Date,
        required: true,
        default: Date.now()
    },
    active: {
        type: Boolean,
        required: true,
        default: true
    },
    logins: [{
        date: Date,
        success: Boolean,
        ip: String,
        deviceType: String,
        deviceName: String
    }],
});

module.exports = mongoose.model('User', UserSchema, 'users');
