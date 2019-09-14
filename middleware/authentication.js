const jwt = require('jsonwebtoken');
const env = require('../environment');
const Blacklist = require('../models/BlackList');

module.exports = {
    isValidToken: (req, res, next) => {
        const bearerHeader = req.headers['authorization'];

        if (bearerHeader) {
            const bearer = bearerHeader.split(' ');

            if (bearer.length !== 2) {
                return res.status(422).json({error: "Bearer token is weirdly formatted."});
            }

            req.token = bearer[1];
            next();
        } else {
            return res.status(422).json({error: "Bearer header is missing."});
        }
    },
    verifyToken: async (req, res, next) => {
        jwt.verify(req.token, env.jwt.secret, (err, authData) => {
            if (err) {
                return res.status(401).json({error: "Bearer token is invalid."});
            } else {
                req.payload = authData;
                next();
            }
        });
    },
    checkBlacklist: async (req, res, next) => {
        const result = await Blacklist.findOne({token: req.token});
        if (result) {
            res.sendStatus(401)
        } else {
            next();
        }
    }
};
