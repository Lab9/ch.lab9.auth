/**
 * Import required packages
 * @type {createApplication}
 */
const express = require('express');
const router = express.Router();
const env = require('../config');
const User = require('../models/User');
const Blacklist = require('../models/BlackList');
const crypto = require('crypto');
const algorithm = "aes-256-cbc";
const key = Buffer.from(env.CRYPTO.SECRET);
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const uuid = require('uuid/v4');
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
 * Otherwise create a salt and a random secret that is unique and user specific and save
 * the user into the database.
 *
 * Last but not least, create a bearer token based on the user data and return it.
 */
router.post('/register', [
    check('email').isEmail().isLength({min: 7}),
    check('password').isLength({min: 8}),
    check('confirmation').isLength({min: 8})], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({errors: errors.array()});
    }

    // Extract data out of the req.body object
    const {email, password, confirmation, type = "lua"} = req.body;

    // check passwords match
    if (password !== confirmation) {
        return res.status(422).json({error: "Passwords do not match."});
    }

    if (await checkUserExists(email)) {
        return res.status(422).json({error: 'Email is already in use'})
    } else {
        const newUser = await createUser(email, password, type);
        return res.status(200).json({token: createBearerToken(newUser)});
    }
});

/**
 * Create a post route on the router object on
 * /login.
 *
 * Before going into logic, we have to validate the inputs.
 * so check if the email is an actual email and the password has a min length of 8.
 * then check the validation result. If the returned array
 * is not empty, send a 422 Status and the errors back.
 * Otherwise continue and extract email and password out of the body.
 *
 * If all this is done, retrieve the User from the database and validate the password.
 *
 * If they do, set status to 200 and return a json with the token.
 * Otherwise, let the user know that his password is wrong.
 */
router.post('/login', [
    check('email').isEmail().isLength({min: 7}),
    check('password').isLength({min: 8})], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({errors: errors.array()});
    }

    const {email, password} = req.body;

    const user = await User.findOne({email: email});
    if (!Boolean(user)) {
        return res.status(422).json({error: "I don't know Rick, that email looks fake to me."})
    }

    if (!user.active) {
        return res.status(422).json({error: "We've got an inactive over here haven't we. Try verifying your account first."})
    }

    const success = bcrypt.compareSync(password, user.password);

    // Log the login request within the user object
    logLoginFor(user, req, success);
    if (success) {
        user.lastLogin = Date.now();
        await user.save();
        return res.status(200).json({token: createBearerToken(user)});
    } else {
        await user.save();
        return res.json({error: "Damn, that's the wrong password."});
    }
});

/**
 *
 */
router.get('/user', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.mid;
    const user = await User.findById(userId);
    if (Boolean(user)) {
        return res.status(200).json(parseUser(user));
    } else {
        return res.status(422).json({error: "User not found."})
    }
});

/**
 *
 */
router.get('/user/:field', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const field = req.params.field;
    const userId = payload.user.mid;
    const user = await User.findById(userId);
    if (Boolean(user)) {
        const parsedUser = parseUser(user);
        if (field in parsedUser) {
            const result = {};
            result[field] = parsedUser[field];
            return res.status(200).json(result);
        } else {
            return res.status(404).json({error: "Field not found."})
        }
    } else {
        return res.status(422).json({error: "User not found."})
    }
});

/**
 *
 */
router.get('/logout', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.lid;
    await Blacklist.create({token: req.token, lid: userId});
    return res.json({message: "Logged out."});
});

/**
 *
 */
router.get('/validate', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.mid;
    const user = await User.findById(userId);
    return res.status(200).json({valid: user.active});
});

/**
 *
 */
router.get('/validate/admin', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.mid;
    const user = await User.findById(userId);
    return res.status(200).json({valid: user.admin});
});

/**
 *
 */
router.patch('/user', isValidToken, verifyToken, checkBlacklist, async (req, res) => {
    const payload = resolveJWTPayload(req.payload);
    const userId = payload.user.mid;
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
 * @returns {{lastLogin: *, createdAt: *, lid: *, lastUpdate: *, admin: *, active: *, type: *, email: *}}
 */
function parseUser(user) {
    return {
        lid: user.lid,
        type: user.type,
        email: user.email,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt,
        lastUpdate: user.lastUpdate,
        admin: user.admin,
        active: user.active
    }
}

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
 * @param type
 */
async function createUser(email, password, type) {
    const userId = uuid();
    const salt = bcrypt.genSaltSync(16);
    const secret = crypto.randomBytes(64).toString('hex');
    const hash = bcrypt.hashSync(password, salt);
    const newUser = new User({
        lid: userId,
        type: type,
        email: email,
        password: hash,
        secret: secret,
    });
    await newUser.save();
    return newUser;
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
            mid: encrypt(String(user._id)),
            lid: encrypt(String(user.lid)),
            type: encrypt(String(user.type)),
            secret: encrypt(String(user.secret))
        },
        authenticated: Date.now()
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
            mid: decrypt(payload.user.mid),
            lid: decrypt(payload.user.lid),
            type: decrypt(payload.user.type),
            secret: decrypt(payload.user.secret)
        },
        authenticated: payload.authenticated
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
    return _iv.toString('hex') + "x" + encrypted.toString('hex');
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
    const parts = String(cipher).split('x');
    const _iv = Buffer.from(parts[0], 'hex');
    const encryptedText = Buffer.from(parts[1], 'hex');
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), _iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

/**
 * Checks if a user with the specified email exists.
 *
 * @param email the email to check
 * @returns {boolean} true if a user with the correspondent email exist
 */
async function checkUserExists(email) {
    return Boolean(await User.findOne({email: email}));
}

/**
 * Create a bearer token based in the logged in user
 *
 * @param user the user to create the bearer token on
 * @returns {string} the bearer token
 */
function createBearerToken(user) {
    return "Bearer " + jwt.sign(createJWTPayload(user), env.JWT.SECRET);
}


module.exports = router;
