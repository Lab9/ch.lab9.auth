/**
 * Import required packages
 * @type {createApplication}
 */
const express = require('express');
const router = express.Router();
const env = require('../environment');
const User = require('../models/User');
const Blacklist = require('../models/BlackList');
const nodemailer = require('nodemailer');
// Create an email transporter
const transporter = nodemailer.createTransport({
    host: env.mail.host,
    port: env.mail.port,
    secure: env.mail.secure,
    auth: env.mail.auth
});
const crypto = require('crypto');
const algorithm = "aes-256-cbc";
const key = Buffer.from(env.crypto.key);
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');
const {isValidToken, verifyToken, checkBlacklist} = require('../middleware/authentication');

/**
 * Create a post route on the router object
 * on /register.
 *
 * Before going into logic, we have to validate the inputs.
 * so check if the email is an actual email and the passwords have a min length of 8.
 * then check the validation result. If the returned array
 * is not empty, send a 422 Status and the errors back.
 * Otherwise continue and extract email, password and confirmation out of the body.
 *
 * if the passwords do not match, set the status to 422 and return a json, mentioning that
 * the passwords do not match.
 *
 * If all this is done, check if there already is a user registered with that email.
 * If yes, set status to 422 and return a json, saying that the email is already in use.
 * Otherwise create a salt and a random secret that is unique and user specific.
 */
router.post('/register', [
    check('email').isEmail(),
    check('password').isLength({min: 8}),
    check('confirmation').isLength({min: 8})], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({errors: errors.array()});
    }

    // Extract data out of the req.body object
    const {email, password, confirmation} = req.body;

    // check passwords match
    if (password !== confirmation) {
        return res.status(422).json({error: "Passwords do not match."});
    }

    const existingUser = await User.findOne({email: email});
    if (Boolean(existingUser)) {
        return res.status(422).json({error: 'Email is already in use'})
    } else {
        const newUser = await createUser(email, password);
        sendWelcomeEmailTo(email);
        jwt.sign(createJWTPayload(newUser), env.jwt.secret, (err, token) => {
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
        logLoginFor(user, req, success);
        if (success) {
            user.lastLogin = Date.now();
            await user.save();
            jwt.sign(createJWTPayload(user), env.jwt.secret, (err, token) => {
                return res.json({token: `Bearer ${token}`})
            })
        } else {
            await user.save();
            return res.json({error: "Damn, that's the wrong password."});
        }
    }
});

router.get('/user', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.id;
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
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.id;
    await Blacklist.create({token: req.token, userId: userId});
    return res.json({message: "Logged out."});
});

router.get('/validate', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.id;
    const user = await User.findById(userId);
    return res.status(200).json({valid: user.active});
});

router.get('/validate/admin', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.id;
    const user = await User.findById(userId);
    return res.status(200).json({valid: user.admin});
});

// Update Handle
router.patch('/user', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.id;
    const user = await User.findById(userId);
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
            await User.updateOne({_id: userId}, {$set: updates});
            return res.status(200).json({message: 'Success'});
        } else {
            return res.status(200).json({message: 'No updates made.'});
        }
    } else {
        return res.status(500).json({error: "User not found."})
    }
});

/**
 *
 * @param user
 * @param req
 * @param success
 */
function logLoginFor(user, req, success) {
    user.logins.push({
        date: Date.now(),
        success: success,
        ip: req.ip,
        deviceType: req.device.type,
        deviceName: req.device.name
    });
}

/**
 * Creates a new lab9 user in mongodb
 * @param email
 * @param password
 */
async function createUser(email, password) {
    const salt = bcrypt.genSaltSync(16);
    const secret = crypto.randomBytes(64).toString('hex');
    const hash = bcrypt.hashSync(password, salt);
    const newUser = new User({
        email: email,
        password: hash,
        secret: secret,
    });
    await newUser.save();
    return newUser;
}


/**
 * Sends a welcome mail to the registrant.
 * First, create a transporter object, which
 * can be used to send multiple emails,
 * then send the mail to the registrant
 * @param email the registrants mail address
 */
function sendWelcomeEmailTo(email) {
    // Send the email
    transporter.sendMail({
        from: 'noreply@lab9.ch',
        to: `${email}`,
        subject: 'Lab9 Account verification',
        text: 'Welcome!'
    });
}

/**
 * Creates an encrypted payload for the jwt token
 * for additional security.
 *
 * @param user the mongodb user
 * @returns {{id: *, secret: *}}
 */
function createJWTPayload(user) {
    return {
        user: {
            id: encrypt(String(user._id)),
            secret: encrypt(String(user.secret)),
            authenticated: Date.now()
        }
    };
}

/**
 * Decrypt an encrypted jwt payload to it's original
 * values.
 *
 * @param payload
 * @returns {{id: *, secret: *}}
 */
function resolveJWTPayload(payload) {
    return {
        user: {
            id: decrypt(payload.user.id),
            secret: decrypt(payload.user.secret),
            authenticated: payload.user.authenticated
        }
    }
}

/**
 * Encrypts a string via the cypher module
 * and the aes-256-cbc algorithm
 *
 * @param text the string to encrypt
 * @returns {string}
 */
function encrypt(text) {
    const _iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, _iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return _iv.toString('hex') + "#" + encrypted.toString('hex');
}

/**
 * Decrypts a string that was encrypted with the
 * encrypt function above.
 * Uses the cypher module and aes-262-cbc algorithm as well.
 *
 * @param cipher the cipher to decrypt
 * @returns {string}
 */
function decrypt(cipher) {
    const parts = String(cipher).split('#');
    const _iv = Buffer.from(parts[0], 'hex');
    const encryptedText = Buffer.from(parts[1], 'hex');
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), _iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}


module.exports = router;
