import assert from 'assert';
import express from 'express';
import axios from 'axios';

import Authentication from './index.js';

describe('middleware', function () {
    const port = 3000;
    const baseUrl = `http://localhost:${port}`;

    const login = 'testuser';
    const id = 42;

    let auth = null;
    let server = null;
    let app = null;

    async function setup(getUserURL, scopes, mutate) {
        app = express();
        auth = new Authentication(getUserURL);

        app.get('/user200', (req, res) => {
            return res.json({ login, id });
        });

        app.get('/user200Reader', (req, res) => {
            return res.json({ login, id, scopes: 'read' });
        });

        app.get('/user200ReaderWriter', (req, res) => {
            return res.json({ login, id, scopes: ['read', 'write'] });
        });

        app.get('/user200All', (req, res) => {
            return res.json({ login, id, scopes: 'all' });
        });

        app.get('/user401', (req, res) => {
            return res.status(401).json({ message: "bad token" });
        });

        app.get('/', auth.middleware(scopes), (req, res) => {
            if (mutate) {
                mutate(req.user);
            }
            res.status(200).json(req.user);
        });

        return new Promise((resolve) => {
            server = app.listen(port, resolve);
        });
    }

    afterEach(function () {
        server.close();
        auth.close();
    });

    it('should provide user details', async function () {
        await setup(`${baseUrl}/user200`);

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

    async function checkStatus(expected) {
        const token = 'helloworld';
        const options = { headers: { Authorization: `Bearer ${token}` } };

        try {
            const response = await axios.get(baseUrl, options);
            if (expected < 400) {
                assert.equal(response.status, expected);
                return;
            }
            assert.fail(`Should fail with status ${expected}`);
        } catch (err) {
            if (!err.response) {
                throw err;
            }
            assert.equal(err.response.status, expected, err.message);
        }
    }

    it('should deny access when authentication fails', async function () {
        await setup(`${baseUrl}/user401`);
        await checkStatus(401);
    });

    it('should deny access when authorization fails', async function () {
        await setup(`${baseUrl}/user200Reader`, 'write');
        await checkStatus(403);
    });

    it('should allow access with valid scope', async function () {
        await setup(`${baseUrl}/user200Reader`, 'read');
        await checkStatus(200);
    });

    it('should allow access with valid scopes', async function () {
        await setup(`${baseUrl}/user200ReaderWriter`, 'write');
        await checkStatus(200);
    });

    it('should allow access with "all" scope', async function () {
        await setup(`${baseUrl}/user200All`, ['A', 'B']);
        await checkStatus(200);
    });

    it('should not leak per-request user mutations into the cache', async function () {
        let calls = 0;
        await setup(`${baseUrl}/user200ReaderWriter`, 'write', (user) => {
            calls += 1;
            if (calls === 1) {
                user.tampered = true;
            }
        });

        const token = 'helloworld';
        const options = { headers: { Authorization: `Bearer ${token}` } };

        const first = await axios.get(baseUrl, options);
        assert.strictEqual(first.data.tampered, true);
        assert.strictEqual(first.data.cached, false);

        const second = await axios.get(baseUrl, options);
        assert.strictEqual(second.data.tampered, undefined);
        assert.strictEqual(second.data.cached, true);
    });
});

describe('extractAccessToken', function() {
    it('should extract a Bearer token', function() {
        const auth = new Authentication('test');
        const expected = 'testtoken1';
        const req = { get: () => `Bearer ${expected}` };
        const actual = auth.extractAccessToken(req);

        assert.ok(actual);
        assert.strictEqual(actual, expected);
    });
    it('should extract a Basic password', function() {
        const auth = new Authentication('test');
        const expected = 'testtoken2';
        const encoded = Buffer.from(`username:${expected}`, 'utf8').toString('base64');
        const req = { get: () => `Basic ${encoded}` };
        const actual = auth.extractAccessToken(req);

        assert.ok(actual);
        assert.strictEqual(actual, expected);
    });
});
