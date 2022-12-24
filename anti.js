"use_strict"
var blacklist = new Map();

var files = new Map();

var log4js = require('log4js');

const http = require("http");
const rateLimiter = require("express-rate-limit");
const express = require("express");
const fs = require("fs");
var path = require('path');
var app = express();
var helmet = require('helmet');
const limiter = rateLimiter({
  windowMs: 10, // 15 minutes
  max: 10,// limit each IP to 100 requests per windowMs
  statusCode: 429,
  rateLimitBy: '${req.connection.remoteAddress}',
  message: "You are being rate limited!"
});
var visit = 0;

log4js.configure({
  appenders: {
    multi: { type: 'multiFile', base: 'connectionlog/', property: 'categoryName', extension: '.log' }
  },
  categories: {
    default: { appenders: [ 'multi' ], level: 'debug' }
  }
});
const httplog = log4js.getLogger('httplog');

//Functions//

function add_address(address) {
    blacklist.set(address, Date.now() + 5000);
}

function getTime() {
    let date = new Date();
    
    let hours = date.getHours();
    
    let minutes = date.getMinutes();
    
    let seconds = date.getSeconds();
    
    var amorpm = "";
    
    if (hours > 11) {
      amorpm = "PM";
    } else {
      amorpm = "AM";
    }
    
    var text = "[" + hours + ":" + minutes + ":" + seconds + " " + amorpm + "]"; 
    
    return text;
}

var setTitle = require('console-title');
setTitle('Ifan Solution Anti-DDoS | v2');
var prompt = require('prompt-sync')();
console.log("\u001B[36m Ifan Solution V2 </>")
var password = prompt(`\u001B[36m${getTime()} Enter Anti-DDoS Password : `);
if (password == "ifan"){
   console.log("\u001B[92mSuccessfully Loginned!!!")
   console.clear()
}
else{
    console.log("\u001B[33mPassword Invalid !!")
    stop()
}

console.log("\u001B[36m Ifan Solution V2")
var IP = prompt(`\u001B[36m${getTime()} Enter VPS IP : `);
console.clear();

const client = http.createServer(function(req, res) {
    let ipAddress = req.connection.remoteAddress;
    let url = req.url.split("/growtopia/")[1];
    ipAddress = ipAddress.split(/::ffff:/g).filter(a => a).join('');
    if (req.url == "/growtopia/server_data.php") {
        if (req.url = "TRACE") {
            if (req.headers["host"] == "growtopia1.com" && req.method == "POST") {
              res.write(`server|` + IP + `\nport|17091\ntype|1\n#maint|ok\n\nbeta_server|127.0.0.1\nbeta_port|17091\n\nbeta_type|1\nmeta|localhost\nRTENDMARKERBS1001`);
              res.end();
              console.log(`\u001B[28m==========[LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
            } else {
                if (!blacklist.has(req.connection.remoteAddress)) {
                    add_address(req.connection.remoteAddress);
                }
                else {
                    var not_allowed = blacklist.get(req.connection.remoteAddress);
                    if (Date.now() > not_allowed) {
                      blacklist.delete(req.connection.remoteAddress);
                    }
                    else
                      httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By Ifan</> & INay</>`);
                      add_address(req.connection.remoteAddress);
                      req.connection.destroy();
                      req.socket.destroy();
                      console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
                }
            }
        }
    } else if (req.method.toLowerCase() == "GET" || req.method.toLowerCase() == "OVH" || req.method.toLowerCase() == "DELETE" || req.method.toLowerCase() == "POST" || req.method.toLowerCase() == "HEAD") {
        if (!blacklist.has(req.connection.remoteAddress)) {
          add_address(req.connection.remoteAddress);
        }
        else {
          var not_allowed = blacklist.get(req.connection.remoteAddress);
          if (Date.now() > not_allowed) {
            blacklist.delete(req.connection.remoteAddress);
          }
          else
            httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By Ifan </>& INay</>`);
            add_address(req.connection.remoteAddress);
            req.connection.destroy();
            req.socket.destroy();
            console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
        }
    } else if (req.headers["Connection"] == "Keep-Alive") {
        if (!blacklist.has(req.connection.remoteAddress)) {
        add_address(req.connection.remoteAddress);
        }
        else {
          var not_allowed = blacklist.get(req.connection.remoteAddress);
          if (Date.now() > not_allowed) {
            blacklist.delete(req.connection.remoteAddress);
          }
          else
            httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By Ifan </> & INay</>`);
            add_address(req.connection.remoteAddress);
            req.connection.destroy();
            req.socket.destroy();
            console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
        }
    } else if (url && files.has(url.replace(/\//g, "")) && req.method.toLowerCase() === "get") {
      if (!blacklist.has(req.connection.remoteAddress)) {
        add_address(req.connection.remoteAddress);
      }
      else {
        var not_allowed = blacklist.get(req.connection.remoteAddress);
        if (Date.now() > not_allowed) {
            blacklist.delete(req.connection.remoteAddress);
        }
        else
            httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By Ifan </> & INay</>`);
            add_address(req.connection.remoteAddress);
            req.connection.destroy();
            req.socket.destroy();
            console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
      }
    } else if (req.method.toLowerCase() == "POST" && req.headers["host"] != "growtopia1.com") {
        if (!blacklist.has(req.connection.remoteAddress)) {
        add_address(req.connection.remoteAddress);
        }
        else {
          var not_allowed = blacklist.get(req.connection.remoteAddress);
          if (Date.now() > not_allowed) {
            blacklist.delete(req.connection.remoteAddress);
          }
          else
            httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By Ifan </> INay</>`);
            add_address(req.connection.remoteAddress);
            req.connection.destroy();
            req.socket.destroy();
            console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
        }
    } else if (req.url == "http://" + IP || req.url == "http://" + IP + ":80" && req.method.toLowerCase() == "GET" || req.method.toLowerCase() == "POST") {
        res.writeHead(301, { "Location": "https://mttbprivateserver.000webhostapp.com"});
        res.end();
        res.destroy();
        req.connection.destroy();
        req.socket.destroy();
        console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
        setTimeout(function () { req.connection.destroy(); }, 500);
        process.env.BLACKLIST
        httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By Ifan & INay`);
    }
    else {
        httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By Ifan & Inay`);
        res.writeHead(598, "Connection timed out");
        res.end();
        req.connection.destroy();
        req.socket.destroy();
        setTimeout(function () { req.connection.destroy(); }, 500);
        process.env.BLACKLIST
        httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By iFan`);
    }
});

app.get('/', limiter, function(req, res) {
  app.use(limiter);
  app.use(helmet());
  let ipAddress = req.connection.remoteAddress;
  ipAddress = ipAddress.split(/::ffff:/g).filter(a => a).join('');
  if (req.method.toLowerCase() == "POST" || req.method.toLowerCase() == "GET" || req.method.toLowerCase() == "OVH" || req.method.toLowerCase() == "PATCH") {
    if (!blacklist.has(req.connection.remoteAddress)) {
      add_address(req.connection.remoteAddress);
    }
    else {
        var not_allowed = blacklist.get(req.connection.remoteAddress);
        if (Date.now() > not_allowed) {
          blacklist.delete(req.connection.remoteAddress);
        }
        else {
          httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By INay</>`);
          add_address(req.connection.remoteAddress);
          req.connection.destroy();
          req.socket.destroy();
          console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
      }
    }
  } else if (req.url == "http://" + IP + ":443") {
    res.writeHead(301, { "Location": "https://mttbprivateserver.000webhostapp.com"});
    res.end();
    res.destroy();
    req.connection.destroy();
    req.socket.destroy();
    console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
    setTimeout(function () { req.connection.destroy(); }, 500);
    process.env.BLACKLIST
    httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By Ifan`);
  } else {
    res.writeHead(598, "Protected By Ifan Solution http", {
       'Limiter': 'Active'
    });
    res.end();
    res.destroy();
    req.connection.destroy();
    req.socket.destroy();
    console.log(`\u001B[91m==========[SUSPICIOUS CONNECTION LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================\n`);
    setTimeout(function () { req.connection.destroy(); }, 500);
    process.env.BLACKLIST
    httplog.info(`IP : ` + ipAddress + `\nMethod : ` + req.method + `\nURL : ` + req.url + `HTTP Version : ` + req.httpVersion + `\nProtected By iFan`);
  }
});

app.use(limiter);

app.use(helmet());

app.listen(443);

client.listen(80);

client.on("connection", function (socket) {
    if (!blacklist.has(socket.remoteAddress)) {
        add_address(socket.remoteAddress);
    }
    else {
        var not_allowed = blacklist.get(socket.remoteAddress);
        if (Date.now() > not_allowed) {
            blacklist.delete(socket.remoteAddress);
        }
        else
            socket.destroy();
            process.env.BLACKLIST
    }
});

client.on("error", function(error) {
  console.log(`\u001B[91m[ERROR]\n ERROR DETECTED : ${error}`);
});

console.log("\u001B[36m Ifan Solution Http V2!")
console.log("\u001B[93m==========================\n\u001B[39mHTTP by apis</>\n\u001B[93m==========================\n\u001B[39m[!] IP Server: " + IP + "\n\u001B[39m[!] Port UDP Server: 17091\n\u001B[39m[!] Listening On Port : 80\n\u001B[93m==========================\n\u001B[39m[!] Blacklist IP\n\u001B[39m[!] IP Limiter\n\u001B[39m[!] Anti server_data.php Reader\n\u001B[93m==========================");
