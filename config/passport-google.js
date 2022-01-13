const { response } = require('express');
const passport = require('passport');
const  GoogleStrategy = require('passport-google-oauth20');
const User = require('../models/User');

passport.serializeUser((user, done) => {
    done(null, user.id);
});


passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


passport.use(
    new GoogleStrategy({

        // options for strategy
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET



}, (accessToken, refreshToken, profile, done) => {

          // check if user already exists
User.findOne({googleId: profile.id}).then((currentUser) => {
    if(currentUser){
            done(null, currentUser);
    } else {


       User.find({email: profile._json.email }, function(err, result) {
        if(!result[0]){
                // create user in db
                        new User({
                            name: profile.displayName,
                            googleId: profile.id,
                            email: profile._json.email,
                            verified: "true",
                            strategy: "google-oauth-2.0",
                            oauth_profile_picture: profile.photos[0].value,
                            provider: "Google OAuth"
                        }).save().then((newUser) => {
                            done(null, newUser);
                        });
             } else {
                if(result[0].strategy === 'local' || result[0].strategy === 'github-oauth-2.0'){
                    return done(null, false, { message: 'Account for ' + profile._json.email + ' already exists, use ' + result[0].provider + ' to log in.' });
                };
            }
          });
       }
        });
})
);