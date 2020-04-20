// NODE_DEBUG=ammonite-authentication node test.js

const express = require('express');
const app = express();

const authentication = require('./index');

app.get('/', authentication, (req, res) => {
    res.status(200).json(req.user);
});

app.listen(3000, function () {
    console.log('Example app listening on port 3000!')
});