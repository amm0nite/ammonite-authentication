
const util = require('util');
const axios = require('axios');

const debug = util.debuglog('ammonite-authentication');

class Authorization {
    constructor(getUserURL, permission) {
        this.getUserURL = getUserURL;
        this.cache = new Map();
        this.cacheTime = 60 * 1000;
        this.permission = permission;
    }

    async query(accessToken) {
        let options = {
            headers: {
                'Authorization': 'Bearer ' + accessToken
            }
        };

        const response = await axios.get(this.getUserURL, options);
        return response.data;
    }

    extractAccessToken(req) {
        var token = req.get('Authorization');
        if (!token) {
            return null;
        }

        var bearerPrefix = 'Bearer';
        if (token.startsWith(bearerPrefix)) {
            token = token.substring(bearerPrefix.length).trim();
        }

        debug('token: ' + token);
        return token;
    };

    authenticate(req, res, next) {
        let accessToken = this.extractAccessToken(req);

        if (!accessToken) {
            return res.status(403).json({ 'message': 'no token' });
        }

        const cached = this.cache.get(accessToken);
        if (cached) {
            req.user = cached.data;
            req.user.cached = true;
            return next();
        }

        debug('refreshing user from api');
        this.query(accessToken).then((data) => {
            data.uid = data.id;
            data.access_token = accessToken;
            data.cached = false;

            const timeout = setTimeout(() => this.cache.delete(accessToken), this.cacheTime);
            this.cache.set(accessToken, { time: Date.now(), data, timeout });

            req.user = data;
            return next();
        }).catch((err) => {
            debug(err);
            return res.status(401).json({ message: err.message });
        });
    }

    authorize(req, res, next) {
        if (!this.permission) {
            return next();
        }

        if (req.user.permission === this.permission) {
            return next();
        }

        if (req.user.permission === 'all') {
            return next();
        }

        return res.status(403).json({ message: 'no permission' });
    }

    close() {
        for (const session of this.cache.values()) {
            clearTimeout(session.timeout);
        }
    }

    middleware() {
        return (req, res, next) => {
            this.authenticate(req, res, () => {
                this.authorize(req, res, next);
            });
        };
    }
}

module.exports = Authorization;
