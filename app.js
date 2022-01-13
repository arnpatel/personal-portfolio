const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const flash = require('connect-flash');
const session = require('express-session');
const logger  = require("morgan");
const  layout  = require("express-layout");
const compression = require('compression');
const { ensureAuthenticated, ensureTotp, ensureVerified } = require('./config/auth');
require('dotenv').config()
const passportGoogle = require('./config/passport-google');
const passportGithub = require('./config/passport-github');
const { cookie } = require('request');

var app = express();
app.use(compression());
require('dotenv').config()

// Turn off X-powered by header
app.disable('x-powered-by');



// Passport Config
require('./config/passport')(passport);

// DB Config
const db = require('./config/keys').mongoURI;

// Connect to MongoDB
mongoose
  .connect(
    db,
    { useNewUrlParser: true ,useUnifiedTopology: true}
  )
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

// EJS
app.set("views", __dirname + "/views");
app.set("view engine", "ejs");

// Express body parser
app.use(express.urlencoded({ extended: true }));

// Express session
app.use(
  session({
    name: 'arthpatel',
    secret: 'i will become an engineer one day',
    resave: true,
    saveUninitialized: true
    
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Connect flash
app.use(flash());

// Global variables
app.use(function(req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

//Helper

app.locals.menuItem = function(req, id, title) {
  return "<a"
    + (req.path === "/" + id ? " class=\"current\"" : "")
    + " href=\"/" + id + "\">"
    + title
    + "</a>";
};

// Configuration

app.use(logger("dev"));
app.use(express.static(__dirname + "/public"));

app.use(layout());
app.use(function(req, res, next) {
  res.locals.req = req;
  next();
});



// Routes
app.use('/', require('./routes/index.js'));
app.use('/auth', require('./routes/authapi.js'));
app.use('/user', require('./routes/user.js'));
// 404 page
app.get("*", function(req, res) {
  res.render("404", { title: "404 Not Found", user: req.user, route: req._parsedOriginalUrl.path});
});
//error page
app.use(function(err, req, res, next){
  res.render('error', { title: "500 Internal Server Error", user: req.user, route: req._parsedOriginalUrl.path });
});


const PORT = 3000;

app.listen(PORT, console.log(`Server started on port ${PORT}`));