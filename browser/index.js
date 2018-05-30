'use strict';

const bodyParser = require('body-parser');
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const process = require('process');
const puppeteer = require('puppeteer');
const uuidv4 = require('uuid/v4');

const app = express();
const port = 5050;

const funcName = process.env.FUNCTION_NAME || 'cyrizm';

let wsEndpoint;

app.use(bodyParser.json());
app.use(helmet());
app.use(morgan('combined'));

app.post('/xss', (req, res) => {
    const body = req.body;
    body.method = body.method || 'GET';
    puppeteer.connect({
        'browserWSEndpoint': wsEndpoint,
        'ignoreHTTPSErrors': true
    }).then(async browser => {
        const id = uuidv4();
        const page = await browser.newPage();

        page.on('console', msg => {
            if (msg.text() === id) res.end('1');
        });

        await page.evaluateOnNewDocument(`window.${funcName} = function () {console.log("${id}")};`);

        if (body.headers) {
            await page.setExtraHTTPHeaders(body.headers);
        }

        if (body.method !== 'GET') {
            await page.setRequestInterception(true);
            page.on('request', request => {
                const overrides = {};
                console.log("request to:", request.url());
                if (request.url() === body.url) {
                    overrides.method = body.method;
                    overrides.headers = body.headers;
                    overrides.postData = body.body;
                }
                request.continue(overrides);
            });

            page.on('response', response => {
                console.log("response from:", response.url());
            });
        }

        await page.goto(body.url, {
            waitUntil: ['load', 'networkidle0']
        });

        //Onload execute is already can be detected
        //Check event-listeners and href
        await page.evaluate(
            `document.querySelectorAll('*').forEach(node => {
    Array.from(node.attributes).filter(a => (a.name.startsWith("on") || a.name === 'href') && a.value.search("${funcName}") > -1).forEach(e => eval(e.value));
});`);

        await browser.disconnect();

        res.end('0');
    });
});

puppeteer.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-xss-auditor']
}).then(browser => {
    wsEndpoint = browser.wsEndpoint();
    browser.disconnect();
    app.listen(port, () => console.log(`listening on port ${port}!`));
});
