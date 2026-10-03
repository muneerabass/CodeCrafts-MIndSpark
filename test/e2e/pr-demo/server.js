// depguard end-to-end test fixture: deliberately insecure code. Do not merge.
const express = require('express');
const https = require('https');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'app', database: 'shop' });

app.get('/orders', (req, res) => {
  db.query("SELECT * FROM orders WHERE customer = '" + req.query.customer + "'", (err, rows) => res.json(rows));
});

app.get('/calc', (req, res) => {
  const result = eval(req.query.expr);
  res.send(String(result));
});

app.get('/proxy', (req, res) => {
  https.get(req.query.url, { rejectUnauthorized: false }, (r) => r.pipe(res));
});

app.listen(3000);

// Hard-coded credentials (test fixture).
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
