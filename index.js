require("./utils.js");
require('dotenv').config();

const session = require('express-session');
const MongoStore = require('connect-mongo');
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const saltRounds = 12;
const port = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000;
const Joi = require("joi");

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("ClusterA1");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/Cluster1`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.use(session({
    secret: node_session_secret,
    saveUninitialized: false,
    resave: true,
}));

app.get('/', (req, res) => {
    var html = `
    <a href='/createUser'>Sign Up</a>
    <br>
    <a href='/login'>Log In</a>
  `;
    res.send(html);
});


app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

// app.get('/about', (req, res) => {
//     var color = req.query.color;

//     res.send("<h1 style='color:" + color + ";'>Patrick Guichon</h1>");
// });

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});


app.get('/createUser', (req, res) => {
    var html = `
    Sign Up
    <br>
    <form action='/members' method='post'>
    <input name='username' type='text' placeholder='username'>
    <br>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req, res) => {
    var html = `
    Log In
    <br>
    <br>
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <br>
    <button>Submit</button>
    <br>
    <br>
    <br>
    ${req.query.msg ? '<div>Invalid email/password combination.</div>' : ''}
    </form>
    `;
    res.send(html);
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    const html = `
  <html>
    <body>
      <h1>Welcome, ${req.session.username}!</h1>
      <br>
      <div id="catBox"><img src="http://edgecats.net/${Math.random()}"/></div>
      <br>
      <a href="/logout">Sign Out</a>
    </body>
  </html>
  `;
    res.send(html);
});

app.post('/members', async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().max(20).required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/createUser');
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
    });
    console.log('Inserted user through members');

    const html = `
    <html>
      <body>
        <h1>Hello, ${username}</h1>
        <br>
        <div id="catBox"><img src="http://edgecats.net/${Math.random()}"/></div>
        <br>
        <a href="/logout">Sign Out</a>
      </body>
    </html>
  `;
    res.send(html);
});


app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().max(20).required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const user = await userCollection.findOne({ email: email });

    if (!user) {
        console.log("user not found");
        res.redirect("/login?msg=Invalid%20email/password%20combination");
        return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = user.username;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        return;
    }
    else {
        console.log("Invalid email/password combination");
        res.redirect("/login?msg=Invalid%20email/password%20combination");
        return;
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    var html = `
    You are logged out.
    `;
    res.send(html);
});

app.get('/cat/:id', (req, res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: " + cat);
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 