import util from 'util';
import axios from 'axios';

const debug = util.debuglog('ammonite-authentication');

export default class Auth {
    constructor(getUserURL) {
        this.getUserURL = getUserURL;
        this.cache = new Map();
        this.cacheTime = 60 * 1000;
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
        let token = req.get('Authorization');
        if (!token) {
            return null;
        }

        const basicPrefix = 'Basic';
        const bearerPrefix = 'Bearer';

        if (token.startsWith(basicPrefix)) {
            const encoded = token.substring(basicPrefix.length).trim();
            const decoded = Buffer.from(encoded, 'base64').toString('utf8');
            const parts = decoded.split(':');
            if (parts.length !== 2) return null;
            token = parts[1];
        }
        if (token.startsWith(bearerPrefix)) {
            token = token.substring(bearerPrefix.length).trim();
        }

        debug('token: ' + token);
        return token;
    };

    async authenticate(req) {
        let accessToken = this.extractAccessToken(req);

        if (!accessToken) {
            const err = new Error('no token');
            err.status = 401;
            err.wwwAuthenticate = 'Bearer';
            throw err;
        }

        const cached = this.cache.get(accessToken);
        if (cached) {
            req.user = { ...cached.data, cached: true };
            return;
        }

        try {
            debug('refreshing user from api');
            const rawData = await this.query(accessToken);
            const userData = {
                ...rawData,
                uid: rawData.id,
                access_token: accessToken,
            };

            const timeout = setTimeout(() => this.cache.delete(accessToken), this.cacheTime);
            this.cache.set(accessToken, { time: Date.now(), data: userData, timeout });

            req.user = { ...userData, cached: false };
        } catch (err) {
            err.status = 401;
            throw err;
        }
    }

    normalizeScopes(scopes) {
        if (!scopes) {
            return [];
        }
        if (typeof scopes === 'string') {
            return [scopes];
        }
        if (!Array.isArray(scopes)) {
            throw new Error('scopes should be an array');
        }
        return scopes;
    }

    async authorize(scopes, req) {
        const userScopes = this.normalizeScopes(req.user.scopes);

        if (userScopes.includes('all')) {
            return;
        }

        const serverScopes = this.normalizeScopes(scopes);

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

    middleware(scopes) {
        return (req, res, next) => {
            Promise.resolve().then(() => {
                return this.authenticate(req)
            }).then(() => {
                return this.authorize(scopes, req);
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
        if (status === 401 && err.wwwAuthenticate) {
            res.set('WWW-Authenticate', err.wwwAuthenticate);
        }
        return res.status(status).json({ message });
    }
}
