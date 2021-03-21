
const util = require('util');
const request = require('request');

const debug = util.debuglog('ammonite-authentication');

class Authorization {
    constructor(getUserURL) {
        this.getUserURL = getUserURL;
        this.cache = [];
    }

    query(accessToken) {
        let options = {
            uri: this.getUserURL,
            headers: {
                'Authorization': 'Bearer ' + accessToken
            },
            json: true
        };

        return new Promise((resolve, reject) => {
            request(options, function (err, res) {
                if (err) return reject(err);

                if (res.statusCode != 200) {
                    let error = new Error('request failed');
                    error.body = res.body;
                    return reject(error);
                }

                return resolve(res.body);
            });
        });
    }

    removeFromCache(accessToken) {
        this.cache = this.cache.filter((element) => element.accessToken !== accessToken);
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

    handle(req, res, next) {
        let accessToken = this.extractAccessToken(req);

        if (!accessToken) {
            return res.status(403).json({ 'message': 'no token' });
        }

        const cached = this.cache.find((element) => element.accessToken === accessToken);
        if (cached) {
            req.user = cached.data;
            return next();
        }

        debug('refreshing user from api');
        this.query(accessToken).then((data) => {
            data.uid = data.id;
            data.access_token = accessToken;

            this.cache.push({ time: Date.now(), accessToken, data });
            setTimeout(() => this.removeFromCache(accessToken), 60 * 1000);

            req.user = data;
            return next();
        }).catch((err) => {
            debug(err);
            let message = err.message;
            if (err.body && err.body.message) {
                message = err.body.message;
            }
            return res.status(401).json({ message });
        });
    }

    middleware() {
        return (req, res, next) => {
            return this.handle(req, res, next);
        };
    }
}

module.exports = Authorization;
