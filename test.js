// NODE_DEBUG=ammonite-authentication node test.js

const axios = require('axios');
const express = require('express');
const app = express();

const port = 3000;
const baseUrl = `http://localhost:${port}`;

const Authentication = require('./index');
const auth = new Authentication(`${baseUrl}/user`);

app.get('/user', (req, res) => {
    //return res.status(404).json({ message: 'not found' });
    return res.json({
        "login": "bob",
        "id": 11,
    });
});

app.get('/', auth.middleware(), (req, res) => {
    res.status(200).json(req.user);
});

const server = app.listen(port, function () {
    console.log('Example app listening on port ' + port);

    const token = 'helloworld';
    const options = { headers: { Authorization: `Bearer ${token}` } };

    axios.get(baseUrl, options).then((res) => {
        console.log(res.data);
        auth.close();
        server.close();
    }).catch((err) => {
        console.log(err);
        auth.close();
        server.close();
    });
});
