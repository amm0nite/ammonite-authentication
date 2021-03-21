// NODE_DEBUG=ammonite-authentication node test.js

const express = require('express');
const app = express();

const port = 3000;

const Authentication = require('./index');
const auth = new Authentication('http://localhost:' + port + '/user');

app.get('/user', (req, res) => {
    return res.json({
        "login": "bob",
        "id": 11,
        "uid": 22,
    });
});

app.get('/', auth.middleware(), (req, res) => {
    res.status(200).json(req.user);
});

app.listen(port, function () {
    console.log('Example app listening on port ' + port)
});
