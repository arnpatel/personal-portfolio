const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const { check, validationResult } = require('express-validator');
const {forwardAuthenticated, ensureAuthenticated } = require('../config/auth');
var async = require('async');
const speakeasy = require('speakeasy');
const request = require('request');
const crypto = require('crypto');
const { encrypt } = require('../crypto/encryption-module');
const rateLimit = require("express-rate-limit");
var complexity = require('complexity');


var app = express();



// Rate limiting Authentication routes.
const limiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 100 requests per windowMs,
  message: 'Error 429 (Too Many Requests): <br/><br/> Halt your horses, you exceeded the rate limit momentarily. Try accesing the route again in half an hour. <br/><br/> Sincerely, <br/> AP Technologies'
});




// Load User model
const User = require('../models/User');
const LoginHistory = require('../models/LoginHistory');
const { use } = require('passport');


// Mailgun variables initialization
var apiKey = process.env.MAILGUN_PRIVATE_KEY;
var domain = 'arthnpatel.com';
const mailgun = require('mailgun-js')({ domain, apiKey });





// Login Page
router.get('/login', forwardAuthenticated, (req, res) => {
res.render('login', {title: "Login", user: req.user, redirectUrl: req.query.continue});
});

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register', {title: "Register", user: req.user}));

// Register
router.post('/register', limiter, [
    
// Special validation to check email input
  check('email','email must be in format xyz@arthnpatel.com').isEmail()
],(req, res) => {


    // Password requirments initiation
    var options = {
      uppercase    : 1,  // A through Z
      lowercase    : 1,  // a through z
      special      : 1,  // ! @ # $ & *
      digit        : 1,  // 0 through 9
      alphaNumeric : 1,  // a through Z
    }
    var passwordComplexity = complexity.checkError(req.body.password, options);


  request.post(
    'https://www.google.com/recaptcha/api/siteverify',
    {
        form: {
            secret: process.env.RECAPTCHA_SECRET,
            response: req.body['g-recaptcha-response']
        }
    },
    function (error, response, body) {
      const recaptcha = JSON.parse(body);
        if (!recaptcha.score || recaptcha.score < 0.3) {
          req.flash('error_msg' , 'No valid input received, or suspicious bot activity was detected.')
          res.redirect('/auth/register');
        } else {
          console.log(body);

  let errors = [];
  const emailError = validationResult(req);
    
    
  
  const { name, email, password, password2 } = req.body;
  

  if (name.length < 6) {
    errors.push({ msg: 'Name must be at least 6 characters' });
  }

  if(!emailError.isEmpty()){
    errors.push({msg: 'The email must be in format xyz@arthnpatel.com'});

  
  }

  if (!password) {
    errors.push({ msg: 'Please create a password' });
  }

  if(password) {

  if (password.length < 8) {
      errors.push({ msg: 'Password must be at least 8 characters' });
  }

  if (passwordComplexity.uppercase === false) {
    errors.push({ msg: 'Password must contain an uppercase value' });
  }

  if (passwordComplexity.lowercase === false) {
    errors.push({ msg: 'Password must contain a lowercase value' });
  }

  if (passwordComplexity.digit === false) {
    errors.push({ msg: 'Password must contain a number' });
  }

  if (passwordComplexity.special === false) {
    errors.push({ msg: 'Password must contain a special character' });
  }

  if(passwordComplexity.uppercase === true & passwordComplexity.lowercase === true & passwordComplexity.digit === true & passwordComplexity.special === true) {

    if (password != password2) {
      errors.push({ msg: 'Passwords do not match' });
    }
  
  }

}


  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2,
      title: "Register",
      user: req.user
    });
  } else {
    User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'The email is already registered' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2,
          title: "Register",
          user: req.user
        });
      } else {
        var registrationVerification = crypto.randomBytes(64).toString('hex');
        const newUser = new User({
          name,
          email,
          password,
          registrationVerification,
          strategy : "local",
          provider: "username and password"
        });

        // Getting first name from the full name
      var fName  = name.split(" "),
      firstName = fName.shift()

        // SEND THE CONFIRMATION EMAIL// 

        mailgun.messages().send({
          from: 'Arth Patel <accounts@arthnpatel.com>',
          to: req.body.email,
          subject: "Please verify your email address.",
          text: 'Hi ' + firstName + ',\n\n' + // plain text body
          'We just need to verify your email address before your signup is complete. Please click the link below.\n\n' +
          'https://' + req.headers.host + '/auth/register_success/' + registrationVerification + '\n\n' +
          'Best,\n' +
          'Arth Patel',
        }).
        then(res => console.log(res)).
        catch(err => console.err(err));

      // SENDING EMAIL TRANSPORTER ENDS HERE

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                req.flash(
                  'success_msg',
                  'You are now registered and can log in'
                );
                res.redirect('/auth/login');
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  }
}
}
)
});



// Registration Verification - GET Request
router.get('/register_success/:token', ensureAuthenticated, (req,res) => {
  User.findOne({ registrationVerification: req.params.token}, function(err, user) {
  if(user.verified === 'true') {

    req.flash('success_msg', 'Your account is already verified. Please continue to dashboard.');
      return res.redirect('/');
   

  } else if(user.email != req.user.email) {
    req.flash('error_msg', 'Please log in with the account that was entitled for the verification link.');
        return res.redirect('/user/dashboard');
  } else {
    User.findOne({ registrationVerification: req.params.token}, function(err, user) {
      if (!user) {
        req.flash('error_msg', 'The email verification link is invalid.');
        return res.redirect('/auth/login');
      } else{
       user.verified = "true";
       user.save(function (err) {
        if(err) {
            console.error('ERROR!');
        }
        req.flash('success_msg', 'Your account is now verified. Please continue to dashboard.');
      return res.redirect('/');
  
    });
  
      }
    })
  }
})
});




// Login
router.post('/login', [
  // Special validation to check email input
  check('email','email must be in format xyz@arthnpatel.com').isEmail()
],(req, res, next) => {

  request.post(
    'https://www.google.com/recaptcha/api/siteverify',
    {
        form: {
            secret: process.env.RECAPTCHA_SECRET,
            response: req.body['g-recaptcha-response']
        }
    },
    function (error, response, body) {
      const recaptcha = JSON.parse(body);
      if (!recaptcha.score || recaptcha.score < 0.3) {
        req.flash('error_msg' , 'No valid input received, or suspicious bot activity was detected.')
        res.redirect('/auth/login');
      } else {
    
    const emailError = validationResult(req);
    
    if (!req.body.email || !req.body.password) {
      if(!req.query.continue) {
        req.flash('error_msg', 'Please enter all fields.');
        return res.redirect('/auth/login');
      } else {
        req.flash('error_msg', 'Please enter all fields.');
        return res.redirect('/auth/login?continue=' + req.query.continue + '&entry=SecureLogin&api=AP-Technologies');
      }
    }
    
    if(!emailError.isEmpty()){
    if(!req.query.continue) {
      req.flash('error_msg', 'Email must be in format xyz@arthnpatel.com');
      return res.redirect('/auth/login');
    } else {
      req.flash('error_msg', 'Email must be in format xyz@arthnpatel.com');
      return res.redirect('/auth/login?continue=' + req.query.continue + '&entry=SecureLogin&api=AP-Technologies');
    }
  }
    else {
      User.findOne({ email: req.body.email }, function(err, user) {
        if(!user){
          req.flash('error_msg', 'Invalid email or password.');
            return res.redirect('/auth/login');
        } else {
        if(user.totp_status === "Yes") {

          bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
            if (isMatch) {
              const hash = encrypt(req.body.password);

              console.log(hash);
              let update = {"totp_iv": hash.iv, "totp_iv_expiry": new Date().getTime() + 60000, "totp_login_password": hash.content};
              var conditions = {email: req.body.email};
              User.updateOne(conditions, update)
              .then(doc => {
                if(!doc) { return res.status(404).end();}
                res.render("authmfa", { title: "Multi-factor Authentication", name: user.name, email: user.email ,user: req.user, totpUser: req, redirectUrl: req.query.continue, password: hash.content});
              })
            } else {
              req.flash('error_msg', 'Invalid email or password.');
            return res.redirect('/auth/login');
            }
          });

          
        } else { 

          if(user.strategy === 'github-oauth-2.0' || user.strategy === 'google-oauth-2.0') {
            req.flash('error_msg', 'Account already exists. Use ' + user.provider + ' to log in.' );
            return res.redirect('/auth/login');
          } else {



            
          // Last login date
          app.set('trust proxy', true);
          var ipAddress = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
          let URL = "https://www.ipapi.co/" + ipAddress + "/json";
          var parameters = {"last_login": new Date().toLocaleString(), "last_login_ip": ipAddress}
          User.update({email: req.body.email}, parameters)
        .then(doc => {
          if(!doc) { return res.status(404).end();}
        })

        // Saving log in to LoginHistory
        var loginParams = {"userEmail": req.body.email, "ipAddress": ipAddress};
        var loginData = new LoginHistory(loginParams);
        loginData.save()
        .then(item => {
          console.log('Item saved.')
        })

        

            
          passport.authenticate('local', {
            successRedirect: req.query.continue || '/user/dashboard',
            failureRedirect: '/auth/login',
            failureFlash: true
            })(req, res, next);
        }
      }
    }
      });
    }
    
    }
}
)
});




// Logout
router.get('/logout', (req, res) => {
  req.logout();
      req.flash('success_msg', 'You are now logged out.');
      res.redirect('/auth/login');
});


// Forgot Page - GET handling

router.get('/forgot', function(req, res) {
  res.render('forgot', {
    user: req.user,
    title: "Forgot Password"
  });
});




// Forgot Page - POST handling
router.post('/forgot', limiter, [
  // Special validation to check email input
  check('email','email must be in format xyz@arthnpatel.com').isEmail()
],function(req, res, next) {


  request.post(
    'https://www.google.com/recaptcha/api/siteverify',
    {
        form: {
            secret: process.env.RECAPTCHA_SECRET,
            response: req.body['g-recaptcha-response']
        }
    },
    function (error, response, body) {
      const recaptcha = JSON.parse(body);
        if (!recaptcha.score || recaptcha.score < 0.3) {
          req.flash('error_msg' , 'No valid input received, or suspicious bot activity was detected.')
          res.redirect('/auth/forgot');
        } else {

  const emailError = validationResult(req);
    
    
    if (!req.body.email) {
      req.flash('error_msg', 'The email field cannot be empty.');
      return res.redirect('/auth/forgot');
    };
    if(!emailError.isEmpty()){
      req.flash('error_msg', 'Email must be in format xyz@arthnpatel.com');
      return res.redirect('/auth/forgot');

    
    }

  else {

  
  async.waterfall([
    function(done) {
      crypto.randomBytes(50, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {

        if (!user) {
          req.flash('success_msg',  'If the account exists, an e-mail will be sent with further instructions.');
          res.redirect('/auth/forgot');
        } else {

        if(user.provider === 'Google OAuth' || user.provider === 'Github OAuth') {
          req.flash('error_msg',  'Password reset option not available. Please use OAuth to log in.');
          res.redirect('/auth/forgot');
        } else {
          user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 1800000; // 1 hour
        user.save(done);
        }

      }
      });
    },
    function(token, user, done) {


      // SEND THE CONFIRMATION EMAIL// 


      mailgun.messages().send({
        from: 'Arth Patel <accounts@arthnpatel.com>',
        to: req.body.email,
        subject: "Password Reset Request",
        text: 'Hello,\n\n' +
        'You are receiving this email because you requested to reset the password for your account.\n\n' +
        'Please click on the link below, or paste this into your browser to complete the process. The link will expire 30 minutes from when it was requested.\n\n' +
        'https://' + req.headers.host + '/auth/reset/' + token.resetPasswordToken + '\n\n' +
        'If you did not request this, please ignore this email and your password will remain unchanged.\n\n' +
        'Feel free to email me at arth@arthnpatel.com for further support as needed.\n\n' +
        'Best,\n' +
        'Arth\n',
      }).
      then(res => console.log(res)).
      catch(err => console.err(err));

      // Sending password reset request email ends here


      req.flash('success_msg', 'If the account exists, an e-mail will be sent with further instructions.');
      res.redirect('/auth/forgot');
      }
    ], function(err) {
      if (err) return next(err);
      req.flash('error_msg' , 'Bummer, an unexpected error has occured. Please try again.')
      res.redirect('/auth/forgot');
    });
  }
}
}
)
  });

 


// Reset Password Page - GET request

  router.get('/reset/:token', limiter, function(req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
      if (!user) {
        req.flash('error_msg', 'The password reset link is invalid or has expired.');
        return res.redirect('/auth/forgot');
      }
      res.render('reset', {
        email: user.email,
        user: req.user,
        token: req.params.token,
        title: "Password Reset"
      });
    });
  });





// Reset Password - POST request

router.post('/reset/:token', limiter, function(req, res) {

  request.post(
    'https://www.google.com/recaptcha/api/siteverify',
    {
        form: {
            secret: process.env.RECAPTCHA_SECRET,
            response: req.body['g-recaptcha-response']
        }
    },
    function (error, response, body) {
      const recaptcha = JSON.parse(body);
        if (!recaptcha.score || recaptcha.score < 0.4) {
          req.flash('error_msg' , 'Reset denied. You seem to be misusing our authentication systems, try again later.')
          res.redirect('/auth/reset/' + req.params.token);
        } else {


   // Password requirments initiation
   var options = {
    uppercase    : 1,  // A through Z
    lowercase    : 1,  // a through z
    special      : 1,  // ! @ # $ & *
    digit        : 1,  // 0 through 9
    alphaNumeric : 1,  // a through Z
  }
  var passwordComplexity = complexity.checkError(req.body.password, options);

  let errors = [];
  const { password, confirm } = req.body;
  

  if (!password || !confirm) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if(password) {

  if (password.length < 8) {
      errors.push({ msg: 'Password must be at least 8 characters' });
  }

  if (passwordComplexity.uppercase === false) {
    errors.push({ msg: 'Password must contain an uppercase value' });
  }

  if (passwordComplexity.lowercase === false) {
    errors.push({ msg: 'Password must contain a lowercase value' });
  }

  if (passwordComplexity.digit === false) {
    errors.push({ msg: 'Password must contain a number' });
  }

  if (passwordComplexity.special === false) {
    errors.push({ msg: 'Password must contain a special character' });
  }

  if(passwordComplexity.uppercase === true || passwordComplexity.lowercase === true || passwordComplexity.digit === true || passwordComplexity.special === true) {

  if (password != confirm) {
    errors.push({ msg: 'Passwords do not match' });
  }

}

}

var token = encodeURIComponent(req.params.token);

if (errors.length > 0) {
  res.render('reset', {
    errors,
    title: "Reset Password",
    user: req.user,
    token
  });
  }


  else {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error_msg', 'Password reset token is invalid or has expired.');
          return res.redirect('/auth/forget');
        };



        bcrypt.hash(req.body.password, 10, function(err, hash) {
          user.password = hash;
        
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        
        user.save()
              .then(user => {
                req.flash('success_msg', 'Success. Your password has been changed now.');
                return res.redirect('/auth/login');
              });
          });
        });

        var userEmail;
        User.find({ resetPasswordToken: req.params.token}, function (err, results) { 
          if (err){ 
              console.log(err); 
          } 
          else{ 

            // Getting first name from the full name
              var fName  = results[0].name.split(" "),
              firstName = fName.shift()

              // SEND THE CONFIRMATION EMAIL// 


              mailgun.messages().send({
                from: 'Arth Patel <accounts@arthnpatel.com>',
                to: results[0].email,
                subject: "Revision to your AP Technologies Account",
                text: 'Hello ' +  firstName + ',\n\n' + 
                'This is a confirmation that the password for your account ' + results[0].email + ' has just been changed.\n\n' +
                'Please contact arth@arthnpatel.com if you feel suspicious of the change.\n\n' +
                'Best,\n' + 
                'Arth\n',
              }).
              then(res => console.log(res)).
              catch(err => console.err(err));

              // SENDING EMAIL ENDS HERE //

          } 
      }); 

      
    },

    ], function(err) {
      if (err) return next(err);
      req.flash('error_msg' , 'Bummer, an unexpected error has occured. Please try again.')
      res.redirect('/auth/forgot');
    });
  }
}
}
)

  });



  // Email Verifiation
  router.get('/email-verification', ensureAuthenticated, (req, res) => {

    User.findOne({ _id: req.user._id }, function(err, user) {

      if(user.verified === 'true') {
          return res.redirect('/user/profile');
      } else {
        res.render('email-verification', {title: "Email Verification", user: req.user})
      }

    })

  });




// Verifying email from Dashboard - POST request
router.post('/verify-email', function(req, res){
  User.findOne({ _id: req.user.id}, function(err, user) {
   if(!user){
    req.flash('error_msg' , 'An unexpected error has occured. Please try again.');
    res.redirect('/user/dashboard');
   } else {

    // Getting first name from the full name
    var fName  = req.user.name.split(" "),
    firstName = fName.shift()

    // SEND THE CONFIRMATION EMAIL// 


    mailgun.messages().send({
      from: 'Arth Patel <accounts@arthnpatel.com>',
      to: req.user.email,
      subject: "Email Verification required.",
      text: 'Hi ' + fName + ',\n\n' + // plain text body
      'We just need to verify your email address before your account status is verified. Please click the link below.\n\n' +
      'https://' + req.headers.host + '/auth/register_success/' + req.user.registrationVerification + '\n\n' +
      'Best,\n' +
      'Arth Patel',
    }).
    then(res => console.log(res)).
    catch(err => console.err(err));

    // SENDING EMAIL ENDS HERE //


    req.flash('success_msg' , 'The verification email has been resent.');
    res.redirect('/auth/email-verification');
   }

  });
})



// Enrolling in Multi factor authentication - POST request

router.post('/totp-enroll', ensureAuthenticated,(req, res) => {
  User.findOne({ _id: req.user.id}, function(err, user) {
    bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
      if (err) throw err;
      if (isMatch) {
            if(req.user.totp_status === 'Yes'){
              req.flash('error_msg' , 'Authentication is already enabled for the account.');
              res.redirect('/user/mfa');
            } else {
              var secret = speakeasy.generateSecret({
              name: "AP Technologies " + "(" + req.user.email + ")"
              }) 
              
            
              var totp_secret = {"totp_secret" : secret.base32, "totp_status" : req.body.totp, "totp_otpauth_url": secret.otpauth_url, "totp_enrolment_date": new Date()};
            
              var conditions = {_id: req.user.id};
              User.updateOne(conditions, totp_secret)
                .then(doc => {
                  req.flash('success_msg' , 'MFA enrollment successful.');
                res.redirect('/user/mfa');
                })
              }
      } else {
        req.flash('error_msg' , 'The current password is incorrect.');
        res.redirect('/user/mfa');
      }
    });
  })
})





// Multi-factor auth page to verify the token entered from Google Authenticator - POST request
router.post('/mfa', (req, res) => {
  
  User.find({ email: req.body.email}, function (err, user) {

    if(!user[0].totp_secret){
      req.flash('error_msg' , 'Access denied.');
      res.redirect('/user/dashboard');
    } else {
    var verify = speakeasy.totp.verify({
      secret: user[0].totp_secret,
      encoding: 'base32',
      token: req.body.totp
    });;
  
    if(verify === false) {
      req.flash('error_msg' , 'Incorrect TOTP. Use the token provided by your authentication app on your phone and try again.');
      res.redirect('/auth/login');
    } else {



      // Saving log in history
        app.set('trust proxy', true);
        var ipAddress = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        let URL = "https://www.ipapi.co/" + ipAddress + "/json";
        var parameters = {"last_login": new Date().toLocaleString(), "last_login_ip": ipAddress}
        User.update({email: req.body.email}, parameters)
        .then(doc => {
        if(!doc) { return res.status(404).end();}
        })


    // Saving log in to LoginHistory
          var loginParams = {"userEmail": req.body.email, "ipAddress": ipAddress};
          var loginData = new LoginHistory(loginParams);
          loginData.save()
          .then(item => {
          console.log('Item saved.')
          })

    


      passport.authenticate('local', {
        successRedirect: req.query.continue || '/user/dashboard',
        failureRedirect: '/auth/login',
        failureFlash: true
        })(req, res);
    }
  
  }
  });
 })



// Revoke MFA - POST request
router.post('/mfa/revoke', (req, res) => {
  User.findOne({ _id: req.user.id}, function(err, user) {
    bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
      if (err) throw err;
      if (isMatch) {
                if(!req.user.totp_secret){
                  req.flash('error_msg' , 'Access denied.');
                  res.redirect('/user/dashboard');
                } else {
                  var cardChanges = {$unset: { totp_secret: 1, totp_otpauth_url: 1, totp_status: 1} };
                  User.findOneAndUpdate({_id: req.user._id}, cardChanges, 
                        {"new": true, upsert: false, passRawResult: false, 
                          "overwrite": false, runValidators: true, 
                          setDefaultsOnInsert: true})
                    .exec(function(err, result) {
                      if(err) {
                        console.log(err);
                      }
                      if(!result) {
                        console.log('database change not processed due to some error.')
                      }
                      req.flash('success_msg' , 'Your MFA settings have successfully been revoked.');
                      res.redirect('/user/mfa');
                    });
                }
      
      } else {
        req.flash('error_msg' , 'The current password is incorrect.');
        res.redirect('/user/mfa');
      }
    });
  })
});



// Google OAuth routes
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));



router.get('/google/redirect', passport.authenticate('google', {
  failureRedirect: '/auth/login',
  failureFlash: true
}), (req, res) =>{

        // Saving log in to User model
          app.set('trust proxy', true);
              var ipAddress = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
              let URL = "https://www.ipapi.co/" + ipAddress + "/json";
              var parameters = {"last_login": new Date().toLocaleString(), "last_login_ip": ipAddress}
              User.update({_id: req.user._id}, parameters)
            .then(doc => {
              if(!doc) { return res.status(404).end();}
            })

          // Saving user log in history to LoginHistory model
                var loginParams = {"userEmail": req.user.email, "ipAddress": ipAddress};
                var loginData = new LoginHistory(loginParams);
                loginData.save()
                .then(item => {
                  console.log('Item saved.')
                })




res.redirect('/user/dashboard');
})

// Github OAuth Routes


router.get('/github',passport.authenticate('github',{ scope: [ 'user:email' ] }));

router.get('/github/redirect', 
  passport.authenticate('github', { failureRedirect: '/auth/login', failureFlash: true }),
      function(req, res) {
        

        // Saving log in to User model
        app.set('trust proxy', true);
        var ipAddress = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        let URL = "https://www.ipapi.co/" + ipAddress + "/json";
        var parameters = {"last_login": new Date().toLocaleString(), "last_login_ip": ipAddress}
        User.update({_id: req.user._id}, parameters)
      .then(doc => {
        if(!doc) { return res.status(404).end();}
      })



      // Saving user log in history to LoginHistory model
      var loginParams = {"userEmail": req.user.email, "ipAddress": ipAddress};
      var loginData = new LoginHistory(loginParams);
      loginData.save()
      .then(item => {
        console.log('Item saved.')
      })

      
        res.redirect('/user/dashboard');
  });






module.exports = router;
