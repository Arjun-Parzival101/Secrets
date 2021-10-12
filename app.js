//jshint esversion:6
require("dotenv").config(); // Required for Encrypting keys in .env files

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");

const mongoose = require("mongoose");

// Level 5 Security packages
const session = require("express-session"); // For cookies
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
// const encryption = require("mongoose-encryption"); // Requiring mongoose encryption - Level 1 Security Package
// const md5 = require("md5"); // Requiring md5 Hash function - Level 2 Security Package
// const bcrypt = require("bcrypt"); //Requiring bcrypt encryption - Level 3 Security Package
// const saltRounds = 10; // Specifying no. of rounds for shuffling - Level 4 Security Package

const GoogleStrategy = require('passport-google-oauth20').Strategy; // OAuth 2.0
const findOrCreate = require("mongoose-findorcreate");
const { xyz } = require("color-convert");

const app = express();

// console.log(process.env.SECRET); // Accessing environment variables

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Using Session
app.use(session({
    secret: "Thisisourlittlesecret",
    resave: false,
    saveUninitialized: false
}));

// Initializing Passport
app.use(passport.initialize());
app.use(passport.session()); // Generates cookies

mongoose.connect("mongodb+srv://admin-arjun:Test123@cluster0.vipcp.mongodb.net/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String // Used only in Submit Post
});

// For hashing passwords with salts and saving to DB
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate); // mongoose function

const User = new mongoose.model("User", userSchema);
// Creates local login strategy
passport.use(User.createStrategy());
// Serializes & Deserializes user passport
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

// Using Passport with OAuth - Level 6
passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "https://shielded-caverns-39176.herokuapp.com/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //***//
    },
    function(accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
));

/////////////////              GET                //////////////////

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/auth/google", // Google Authentication route
    passport.authenticate("google", { scope: ["profile"] }) // Authenticating user using passport based on user"s Google account
);

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect secrets page.
        res.redirect('/secrets');
    });

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.get("/secrets", function(req, res) {
    User.find({ "secret": { $ne: null } }, function(err, foundUsers) { // Fetching all secrets if secrets exists
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) { // If user found, rendering them to secrets page
                res.render("secrets", { usersWithSecrets: foundUsers });
            }
        }
    });
    // if (req.isAuthenticated()) { // If Authenticated allowing
    //     res.render("secrets");
    // } else { // Else redirecting to login page again
    //     res.redirect("/login");
    // }
});

////////////// SUBMIT /////////////////

//GET//
app.get("/submit", function(req, res) {
    if (req.isAuthenticated()) { // If Authenticated allowing
        res.render("submit");
    } else { // Else redirecting to login page again
        res.redirect("/login");
    }
});

//POST//
app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret; // Fetching user's Secret

    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser) { // Checking if the user exists
        if (err) {
            console.log(err);
        } else {
            if (foundUser) { // If user found
                foundUser.secret = submittedSecret; // Storing secret
                foundUser.save(function() {
                    res.redirect("/secrets");
                }); // Saving their secret
            }
        }
    });
});

app.get("/logout", function(req, res) {
    req.logout(); // Logging out session
    res.redirect("/"); // And redirecting to Home page
});

/////////////////            POST             ///////////////////

// Creating new account for new users
app.post("/register", function(req, res) {

    User.register({ username: req.body.username }, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() { // Authenticating password using Passport
                res.redirect("/secrets");
            });
        }
    });

    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     // Store hash in our password DB.
    //     const newUser = new User({
    //         email: req.body.username, // From the form submit
    //         password: hash // Encrypting using bcrypt salt hashing
    //     });
    //     // Saving new user data to mongoDB
    //     newUser.save(function(err) {
    //         if (!err) {
    //             res.render("secrets"); // Rendering user to Secrets page only after registering/signing up
    //         } else {
    //             res.send(err);
    //         }
    //     });
    // });

});
// User signing in (Already registered users only)
app.post("/login", function(req, res) {
    //Creating User credentials when they login into fields
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    // Authenticating it using Passport
    req.login(user, function(err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function() { // Authenticating password using Passport
                res.redirect("/secrets");
            });
        }
    });

    // const username = req.body.username; // User credentials
    // const password = req.body.password; // User credentials
    // // Checking whether this credentials already exists in DB
    // User.findOne({ email: username }, function(err, foundUser) {
    //     if (err) {
    //         console.log(err);
    //     } else {
    //         if (foundUser) { // Comparing user's password with password in DB using bcrypt compare function
    //             bcrypt.compare(password, foundUser.password, function(err, result) {
    //                 if (result === true) { // If same rendering user to Secret
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //     }
    // });
});

let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}

app.listen(port, function() {
    console.log("Server successfully running on Port: 3000");
});