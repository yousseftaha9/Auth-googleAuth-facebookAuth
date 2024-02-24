//jshint esversion:6
import 'dotenv/config'
import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import ejs from 'ejs';
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FaceBookStrategy } from 'passport-facebook';
//passport-local-mongoose package will salt and hash our
//password for us automatically without us having to do anything about it.
//But in addition, when say I navigate a way to, I don't know, the home page and I tried to access the secrets
//page directly it gets rendered straight away without me needing to login again because I am already
//authenticated and this is all thanks to the cookie that got my session ID saved
const port = 3000;
const app = express();
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'helllo i am youssef.',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
  }));
// After setting up a session => setup a passport(used for authentication)
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true})
.then(console.log("connected to db successfully")).catch(err=>{console.log(err)})

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//This serialize and deserialize will work for all strategies not only local one
// as with the above method
passport.serializeUser(function(user, done) {
    done(null, user);
  });
   
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOne({ googleId: profile.id }).then((foundUser) => {
        if (foundUser) {
          return foundUser;
        } else {
          const newUser = new User({
            googleId: profile.id
          });
          return newUser.save();
        }
      }).then((user) => {
        return cb(null, user);
      }).catch((err) => {
        return cb(err);
      });
  }
));

app.get("/", (req, res)=>{
    res.render("home.ejs");
});

app.get("/auth/google",
passport.authenticate("google", { scope: ["profile"] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login", (req, res)=>{
    res.render("login.ejs");
});

app.get("/register", (req, res)=>{
    res.render("register.ejs");
});

app.get("/secrets", (req, res)=>{
    User.find({"secret": {$ne:null}}).then(foundUsers=>{
        if(foundUsers){
          res.render("secrets", {usersWithSecrets: foundUsers})
        }
    }).catch(err=>{console.log(err);});
});

app.get("/submit", (req, res)=>{
  if(req.isAuthenticated()){
    res.render("submit.ejs");
} else {
    res.redirect("/login");
}
});

app.post("/submit", (req, res)=>{
  const submittedSecret = req.body.secret;
  // console.log(req.user)
  User.findById(req.user._id)
      .then((foundUser) => {
          if (foundUser) {
              foundUser.secret = submittedSecret;
              foundUser.save()
                  .then(() => {
                      res.redirect("/secrets");
                  });
          } else {
              console.log("User not found");
          }
      })
      .catch((err) => {
          console.log(err);
      });
})

app.get("/logout", (req, res)=>{
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
});

app.post("/register", (req, res)=>{
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })
});

app.post("/login", (req, res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.logIn(user, function(err){
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets")
            })
        }
    })
});

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});