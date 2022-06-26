"use strict";

require('dotenv').config({ path: __dirname + "/.env" });  // must be at top. Not used in this file currently.
const express = require("express");
const bodyParser = require('body-parser');
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");                     // note: requiring passport-local is not necessary
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
 
const app = express();

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');  
 
app.use(express.json());       // to support JSON-encoded bodies
app.use(express.urlencoded({ extended: true })); // to support URL-encoded bodies
app.use(bodyParser.urlencoded({extended:true}));

app.use(express.static(__dirname + "/public"));

app.use(session({
    secret: process.env.SECRET, // should be inside an environment variable
    resave: false,
    saveUninitialized: false
}));
 
app.use(passport.initialize());
app.use(passport.session());
 
// "userDB" is the name of the database
// const mongoAtlasUsername = process.env.ATLAS_USERNAME;
// const mongoAtlasPassword = process.env.ATLAS_PASSWORD;

// mongoose.connect("mongodb+srv://" + mongoAtlasUsername + ":" + mongoAtlasPassword + "@cluster0.8gasx.mongodb.net/userDB");
mongoose.connect("mongodb://localhost:27017/userDB", { useUnifiedTopology: true, useNewUrlParser: true } ); 
 
// Create the schema ( == blueprint) for the database.
const userSchema = new mongoose.Schema ({
    email: String,  
    password: String,
    googleId: String,            //for user authentication using google OAuth
    secret: String               //secret submitted by the user
});
 
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
 
const User = mongoose.model("User", userSchema);
 
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
});   
passport.deserializeUser(function(user, done) {
    done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GoogleCLIENT_ID,
    clientSecret: process.env.GoogleCLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {           //returns Access Token and profile
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {      // findOrCreate is not available in mongoose, use mongoose findOrCreate package
      return cb(err, user);             //saving the googleId into DB
    });
  }
));
 
app.get("/",function(req,res) {
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});
 
app.get("/login",function(req,res) {
    res.render("login");
});
 
app.get("/register",function(req,res) {
    res.render("register");
});
 
app.get("/secrets", function(req,res) {
    // The below line was added so we can't display the "/secrets" page
    // after we logged out using the "back" button of the browser, which
    // would normally display the browser cache and thus expose the 
    // "/secrets" page we want to protect. Code taken from this post.
    res.set(
        'Cache-Control', 
        'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
    );
    if(req.isAuthenticated()) {
        User.find({"secret": {$ne: null}}, function(err, foundUsers){
            if (err){
              console.log(err);
            } else {
              if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
              }
            }
        });      
    } else {
        res.redirect("/login");
    }
});

app.get("/submit", function(req,res) {
    if(req.isAuthenticated()) {
        res.render("submit");        
    } else {
        res.redirect("/login");
    }
});
 
//documentation for logout is not updated and have bugs
app.get('/logout', function(req, res, next) {       //get method instead of post
    req.logout(function(err) {                     // logout now requires a callback function
      if (err) { return next(err); }
      res.redirect('/');
    });
});


//--------------------------- Post Methods --------------------------------------------
 
app.post("/register",function(req,res) {
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});
 
// this is the new login route, which authenticates first and THEN
// does the login (which is required to create the session, or so I 
// understood from the passport.js documentation). 
// A failed login (wrong password) will give the browser error 
// "unauthorized".
 
app.post("/login", 
    passport.authenticate("local"), function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password     
    });
    req.login(user, function(err) {
        if(err) {
            console.log(err);
        } else {
            res.redirect("/secrets");
        }
    });
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    //passport saves current user details into request variable
    //console.log(req.user);                 
    User.findById(req.user._id, function(err, foundUser){
        if(err){
            console.log(err);
        } else {
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});
 
// this is the original login route (with the bug):
// app.post("/login",function(req,res){
//     const user = new User({
//         username: req.body.username,
//         password: req.body.password     
//     });
//     req.login(user, function(err){
//         if(err) {
//             console.log(err);
//         } else {
//             passport.authenticate("local")(req, res, function(){
//                 res.redirect("/secrets");
//             });
//         }
//     });
// });
 
app.listen(3000,function(){
    console.log("Server is running on port 3000");
});