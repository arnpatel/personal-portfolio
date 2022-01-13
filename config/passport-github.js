const { response } = require('express');
const passport = require('passport');
const  GitHubStrategy = require('passport-github2').Strategy;
const User = require('../models/User');


passport.serializeUser((user, done) => {
    done(null, user.id);
});


passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });



passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL,
    scope: [ 'user:email', 'read:user'],
  },
  function(accessToken, refreshToken, profile, done) {


      // check if user already exists
       User.findOne({githubId: profile.id}).then((currentUser) => {
        if(currentUser){
                done(null, currentUser);
         } else {




 
    User.find({email: profile.emails[0].value }, function(err, result) {
        if(!result[0]){
            // create user in db
                    new User({
                        name: profile.displayName,
                        githubId: profile.id,
                        githubUsername: profile.username,
                        email: profile.emails[0].value,
                        verified: "true",
                        strategy: "github-oauth-2.0",
                        oauth_profile_picture: profile.photos[0].value,
                        provider: "Github OAuth"
                    }).save().then((newUser) => {
                        done(null, newUser);
                    });
         } else {
            if(result[0].strategy === 'local' || result[0].strategy === 'google-oauth-2.0'){
                return done(null, false, { message: 'Account for ' + profile.emails[0].value + ' already exists, use ' + result[0].provider + ' to log in.' });
            };
          }
        });
        }
      });




  }))