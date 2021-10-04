const assert = require('assert');
const express = require('express');
const axios = require('axios');

const Authentication = require('./index.js');

describe('middleware', function () {
    const port = 3000;
    const baseUrl = `http://localhost:${port}`;

    const login = 'testuser';
    const id = 42;

    let auth = null;
    let server = null;
    let app = null;

    beforeEach(function (next) {
        auth = new Authentication(`${baseUrl}/user200`);

        app = express();

        app.get('/user200', (req, res) => {
            return res.json({ login, id });
        });

        app.get('/user401', (req, res) => {
            return res.status(401).json({ message: "bad token" });
        });

        app.get('/', auth.middleware(), (req, res) => {
            res.status(200).json(req.user);
        });

        server = app.listen(port, () => {
            return next();
        });
    });

    afterEach(function () {
        server.close();
        auth.close();
    });

    it('should provide user details', async function () {
        const token = 'helloworld';
        const options = { headers: { Authorization: `Bearer ${token}` } };

        const firstResponse = await axios.get(baseUrl, options);
        assert.equal(firstResponse.data.login, login);
        assert.equal(firstResponse.data.id, id);
        assert.equal(firstResponse.data.cached, false);

        const secondResponse = await axios.get(baseUrl, options);
        assert.equal(secondResponse.data.login, login);
        assert.equal(secondResponse.data.id, id);
        assert.equal(secondResponse.data.cached, true);
    });

    it('should return unauthorized', async function () {
        auth.getUserURL = `${baseUrl}/user401`;

        const token = 'helloworld';
        const options = { headers: { Authorization: `Bearer ${token}` } };

        try {
            const response = await axios.get(baseUrl, options);
            assert.fail("Should fail as unauthorized");
        } catch (err) {
            assert.equal(err.response.status, 401);
        }
    });
});
