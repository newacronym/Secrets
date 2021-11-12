//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const MongoStore = require('connect-mongo');
const MongoDBStore = require('connect-mongodb-session')(session);
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

// to store sessions in db
// var store = new MongoDBStore({
//   uri: process.env.MONGO_URL,
//   collection: 'mySessions'
// });
// store.on('error', function(error) {
//   console.log(error);
// });


app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: true,
  // if u want to store sessions in db , for this project i am not
  // cookie: {
  //   maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
  // },
  // store: store,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URL);

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  title: [],
  secret: [],
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // https://frozen-brushlands-38603.herokuapp.com
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile.displayName);
    User.findOrCreate({
      username: profile.displayName,
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', {
    scope: ["profile"]
  }));

app.get("/auth/google/secrets",
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({secret: { $ne:null }}, function(err,foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets:foundUsers});
      }
    }
  });
});

app.get("/submit", function(req,res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;
  const submittedSecretTitle = req.body.title;

  User.findById(req.user.id,function(err,foundUser){
    if(!err){
        if(foundUser){
          foundUser.secret.push(submittedSecret);
          foundUser.title.push(submittedSecretTitle);
          foundUser.save(function(){
            res.redirect("/secrets");
          });
        }
    }else{
      console.log(err);
    }
  });
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res) {
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function(req, res) {
  console.log("Server started successfully");
});
