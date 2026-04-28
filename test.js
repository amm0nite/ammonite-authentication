import assert from 'assert';
import express from 'express';

import Authentication from './index.js';

describe('middleware', function () {
    const port = 3000;
    const baseUrl = `http://localhost:${port}`;

    const login = 'testuser';
    const id = 42;

    let auth = null;
    let server = null;
    let app = null;

    async function setup(getUserURL, scopes, mutate, authOptions) {
        app = express();
        auth = new Authentication(getUserURL, authOptions);

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

        app.get('/user500', (req, res) => {
            return res.status(500).json({ message: "upstream failure" });
        });

        app.get('/userSlow', (req, res) => {
            setTimeout(() => res.json({ login, id }), 200);
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

        const firstResponse = await fetch(baseUrl, options);
        const firstUser = await firstResponse.json();
        assert.equal(firstUser.login, login);
        assert.equal(firstUser.id, id);
        assert.equal(firstUser.cached, false);

        const secondResponse = await fetch(baseUrl, options);
        const secondUser = await secondResponse.json();
        assert.equal(secondUser.login, login);
        assert.equal(secondUser.id, id);
        assert.equal(secondUser.cached, true);
    });

    async function checkStatus(expected) {
        const token = 'helloworld';
        const options = { headers: { Authorization: `Bearer ${token}` } };

        const response = await fetch(baseUrl, options);
        assert.equal(response.status, expected);
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

    it('should propagate upstream 5xx errors', async function () {
        await setup(`${baseUrl}/user500`);
        await checkStatus(500);
    });

    it('should time out slow upstream calls', async function () {
        await setup(`${baseUrl}/userSlow`, null, null, { requestTimeout: 50 });
        await checkStatus(502);
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

        const first = await fetch(baseUrl, options);
        const firstUser = await first.json();
        assert.strictEqual(firstUser.tampered, true);
        assert.strictEqual(firstUser.cached, false);

        const second = await fetch(baseUrl, options);
        const secondUser = await second.json();
        assert.strictEqual(secondUser.tampered, undefined);
        assert.strictEqual(secondUser.cached, true);
    });

    it('should respond 401 with WWW-Authenticate when token is missing', async function () {
        await setup(`${baseUrl}/user200`);

        const response = await fetch(baseUrl);
        assert.strictEqual(response.status, 401);
        assert.strictEqual(response.headers.get('www-authenticate'), 'Bearer');
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
