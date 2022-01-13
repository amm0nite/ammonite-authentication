
const util = require('util');
const axios = require('axios');

const debug = util.debuglog('ammonite-authentication');

class Auth {
    constructor(getUserURL, scopes) {
        this.getUserURL = getUserURL;
        this.cache = new Map();
        this.cacheTime = 60 * 1000;
        this.scopes = scopes;
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

    async authenticate(req, res) {
        let accessToken = this.extractAccessToken(req);

        if (!accessToken) {
            const err = new Error('no token');
            err.status = 403;
            throw err;
        }

        const cached = this.cache.get(accessToken);
        if (cached) {
            req.user = cached.data;
            req.user.cached = true;
            return;
        }

        try {
            debug('refreshing user from api');
            const data = await this.query(accessToken);

            data.uid = data.id;
            data.access_token = accessToken;
            data.cached = false;

            const timeout = setTimeout(() => this.cache.delete(accessToken), this.cacheTime);
            this.cache.set(accessToken, { time: Date.now(), data, timeout });

            req.user = data;
        } catch (err) {
            err.status = 401;
            throw err;
        }
    }

    async authorize(req, res) {
        let userScopes = req.user.scopes ?? [];
        if (typeof userScopes === 'string') {
            userScopes = [userScopes];
        }

        if (userScopes.includes('all')) {
            return;
        }

        let serverScopes = this.scopes ?? [];
        if (typeof serverScopes === 'string') {
            serverScopes = [serverScopes];
        }

        for (const scope of serverScopes) {
            if (!userScopes.includes(scope)) {
                const err = new Error(`missing scope ${scope}`);
                err.status = 403;
                throw err;
            }
        }
    }

    close() {
        for (const session of this.cache.values()) {
            clearTimeout(session.timeout);
        }
    }

    middleware() {
        return (req, res, next) => {
            Promise.resolve().then(() => {
                return this.authenticate(req, res)
            }).then(() => {
                return this.authorize(req, res);
            }).then(() => {
                return next();
            })
            .catch((err) => {
                this.handleError(req, res, err);
            });
        };
    }

    handleError(req, res, err) {
        const status = err.status ?? 500;
        const message = err.message;
        return res.status(status).json({ message });
    }
}

module.exports = Auth;
