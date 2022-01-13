const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { decrypt } = require('../crypto/encryption-module');



// Load User model
const User = require('../models/User');

module.exports = function(passport) {
  passport.use(
    new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
      // Match user
      User.findOne({
        email: email
      }).then(user => {
        if (!user) {
          return done(null, false, { message: 'Invalid email or password' });
        }

       
        // Checking for TOTP first

        if(user.totp_status === 'Yes') {
          
          const timestamp_now = new Date().getTime();
          console.log(password);

          if(user.totp_iv_expiry > timestamp_now && password === user.totp_login_password) {

            let hash =  { iv: user.totp_iv, content: password,};
            const text = decrypt(hash);
        
            bcrypt.compare(text, user.password, (err, isMatch) => {
              if (err) throw err;
              if (isMatch) {
                return done(null, user);
              } else {
                return done(null, false, { message: 'The password entered on login page was incorrect. Try again.' });
              }
            });
        
            } else {
              return done(null, false, { message: 'The TOTP login fingerprint has already expired. Please log in again.' });
            }


      } else{



        // Match password
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) throw err;
          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false, { message: 'Invalid email or password' });
          }
        });
      }
      });
    })
  );

  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });
};
