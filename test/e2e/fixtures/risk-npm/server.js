const express = require('express');
const request = require('request');
const app = express();
app.use(express.json());
app.get('/', (req, res) => res.send('ok'));
module.exports = app;
