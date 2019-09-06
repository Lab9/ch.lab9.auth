const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Blacklist = require('../models/BlackList');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const env = require('../environment');
const {check, validationResult} = require('express-validator');
const {isValidToken, verifyToken, verifySession, checkBlacklist} = require('../middleware/authentication');

// Register Handle
router.post('/register', [
    check('email').isEmail(),
    check('password').isLength({min: 8}),
    check('passwordConfirmation').isLength({min: 8})], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({errors: errors.array()});
    }

    // Pull data out of the req.body object
    const {email, password, passwordConfirmation} = req.body;

    // check passwords match
    if (password !== passwordConfirmation) {
        return res.status(422).json({error: "Passwords do not match."});
    }

    const existingUser = await User.findOne({email: email});
    if (Boolean(existingUser)) {
        return res.status(422).json({error: 'Email is already in use'})
    } else {
        const salt = bcrypt.genSaltSync(16);
        const secret = crypto.randomBytes(64).toString('hex');
        const hash = bcrypt.hashSync(password, salt);
        const newUser = new User({
            email: email,
            password: hash,
            secret: secret,
        });
        await newUser.save();
        req.session.userId = newUser._id;
        sendWelcomeEmailTo(email);
        const jwtUser = {
            id: newUser._id,
            secret: newUser.secret
        };
        jwt.sign({user: jwtUser}, env.jwt.secret, (err, token) => {
            res.json({token: `Bearer ${token}`});
        })
    }
});

// Login Handle
router.post('/login', [
    check('email').isEmail(),
    check('password').isLength({min: 8})], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({errors: errors.array()});
    }

    const {email, password} = req.body;

    const user = await User.findOne({email: email});
    if (!Boolean(user)) {
        return res.status(422).json({error: "I don't know Rick, that email looks fake to me."})
    } else {
        if (!user.active) {
            return res.status(422).json({error: "We've got an inactive over here haven't we. Try verifying your account first."})
        }
        const success = bcrypt.compareSync(password, user.password);
        user.logins.push({
            date: Date.now(),
            success: success,
            ip: req.ip,
            deviceType: req.device.type,
            deviceName: req.device.name
        });
        if (success) {
            user.lastLogin = Date.now();
            await user.save();
            req.session.userId = user._id;
            const userToSign = {
                id: user._id,
                secret: user.secret
            };
            jwt.sign({user: userToSign}, env.jwt.secret, (err, token) => {
                return res.json({token: `Bearer ${token}`})
            })
        } else {
            user.save();
            return res.json({error: "Damn, that's the wrong password."});
        }
    }
});

router.get('/user', isValidToken, verifyToken, verifySession, checkBlacklist, async (req, res) => {
    const userId = req.authData.user.id;
    const user = await User.findById(userId);
    if (Boolean(user)) {
        return res.status(200).json({
            id: user._id,
            email: user.email,
            lastLogin: user.lastLogin,
            createdAt: user.createdAt,
            lastUpdate: user.lastUpdate,
            admin: user.admin,
            active: user.active
        });
    } else {
        return res.status(500).json({error: "User not found."})
    }
});

router.get('/logout', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const userId = req.authData.user.id;
    if (req.session) {
        req.session.destroy(err => {
        });
        await Blacklist.create({token: req.token, userId: userId});
        return res.json({message: "Logged out."})
    }
    return res.json({message: "Kinda weird but you failed to log out."})
});

router.get('/validate', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const id = req.authData.user.id;
    const user = await User.findById(id);
    return res.status(200).json({valid: user.active});
});

router.get('/validate/admin', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const id = req.authData.user.id;
    const user = await User.findById(id);
    return res.status(200).json({valid: user.admin});
});

// Update Handle
router.patch('/user', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const id = req.authData.user.id;
    const user = await User.findById(id);
    if (user) {
        const {email, password} = req.body;
        let updates = {};

        if (email) updates.email = email;
        if (password) {
            const salt = bcrypt.genSaltSync(16);
            updates.password = bcrypt.hashSync(password, salt);
        }

        updates.lastUpdate = Date.now();
        if (Object.keys(updates).length > 0) {
            await User.updateOne({_id: id}, {$set: updates});
            return res.status(200).json({message: 'Success'});
        } else {
            return res.status(200).json({message: 'No updates made.'});
        }
    } else {
        return res.status(500).json({error: "User not found."})
    }
});


function sendWelcomeEmailTo(email) {
    const transporter = nodemailer.createTransport({
        host: 'eleven.ssl.hosttech.eu',
        port: 465,
        secure: true,
        auth: {
            user: "noreply@lab9.ch",
            pass: "G9M=*ABm%?m&WMVX"
        }
    });

    transporter.sendMail({
        from: 'noreply@lab9.ch',
        to: `${email}`,
        subject: 'Lab9 Account verification',
        text: 'Welcome!'
    });
}


module.exports = router;
