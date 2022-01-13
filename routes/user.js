const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const methodOverride = require("method-override");
// Load User model
const User = require('../models/User');
const Contact = require('../models/Contact');
const Donation = require('../models/Donation');
const LoginHistory = require('../models/LoginHistory');
const { ensureAdmin, ensureAuthenticated, ensureVerified } = require('../config/auth');
const request = require('request');
const qrcode  = require('qrcode');
const multer = require('multer');
const {v4 : uuidv4} = require('uuid');
const paypal = require('paypal-rest-sdk');
var complexity = require('complexity');


// Mailgun variables
var apiKey = process.env.MAILGUN_PRIVATE_KEY;
var domain = process.env.MAILGUN_DOMAIN;
const mailgun = require('mailgun-js')({ domain, apiKey });



// Paypal rest SDK configuration
// Creating an environment
var client_id = process.env.PAYPAL_CLIENT_ID;
var secret = process.env.PAYPAL_SECRET;
paypal.configure({
  'mode': 'live', //sandbox or live
  'client_id': client_id,
  'client_secret': secret
});



// User Dashboard
router.get('/dashboard', ensureAuthenticated, ensureVerified,  (req, res) =>
  res.render('dashboard', {title: "Dashboard", user: req.user})
);

// User Profile
router.get('/profile', ensureAuthenticated, ensureVerified,(req, res) =>
  res.render('profile', {title: "User Profile", user: req.user})
);

//Edit name from Dashboard - PUT request

router.use(methodOverride("_method", {
    methods: ["POST", "GET"]
  }));
  
  router.put('/dashboard/update/general/:id', ensureAuthenticated, ensureVerified,function(req, res) {
    var token = encodeURIComponent(req.params.id);
    var conditions = {_id: req.params.id};
    var name = req.body.name;
    if(name.length < 6){
      req.flash('error_msg' , 'Name must be at least 6 characters.')
      res.redirect('/user/profile');
    }
    else {
    User.update(conditions, req.body)
    .then(doc => {
      if(!doc) { return res.status(404).end();}
      req.flash('success_msg' , 'Success, The requested information has been changed.')
      res.redirect('/user/profile');
    })
  }
  console.log('error block');
  });


  

//Edit password from Dashboard - PUT request

  router.put('/dashboard/update/password/:id', ensureAuthenticated,ensureVerified, function(req, res) {
    var token = encodeURIComponent(req.params.id);
    if(!req.body.oldpassword) {
      req.flash('error_msg' , 'Please enter the old password')
      res.redirect('/user/profile');
    } else {
    bcrypt.compare(req.body.oldpassword, req.user.password, (err, isMatch) => {
      if (err) throw err;
      if (isMatch) {
        
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
            const { password } = req.body;
  

  if (!password) {
    errors.push({ msg: 'Please enter the new password' });
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

}


var token = encodeURIComponent(req.params.token);

if (errors.length > 0) {
  res.render('profile', {
    errors,
    title: "User Profile",
    user: req.user,
    token
  });
  }
        
        
        else {
          var conditions = {_id: req.params.id};
          bcrypt.hash(req.body.password, 10, function(err, hash) {
              req.body.password = hash;
          User.update(conditions, req.body)
          .then(doc => {
            if(!doc) { return res.status(404).end();}
            else {
              req.flash('success_msg' , 'Success, your password has been changed successfully.')
          res.redirect('/user/profile');
              
            }
          })
          })
        }
      } else {
        req.flash('error_msg' , 'The old password is incorrect.')
      res.redirect('/user/profile');
      }
    });

  }
    
  });




// Admin Dashboard - GET handling
router.get('/admin', ensureAuthenticated,ensureVerified, ensureAdmin, function(req, res) {
    if(!req.user){
      req.flash('error_msg' , 'Access denied.')
      res.redirect('/user/dashboard');
    }
    else{
      var string = encodeURIComponent(req.user.status);
        Contact.find({}, function(err, contactlist) {
          if (err) {
            res.send(err);
          } else {
            let sortedInput = contactlist.slice().sort((a, b) => b.date - a.date);
            let result  = sortedInput;
            res.render('admin', {
              user: req.user,
              result,
              title: "Admin Dashboard"
            });
          }
        });
    }
});



//Admin Dashboard - Deleting contact inquiried - POST request

router.post('/delete-contact', ensureAuthenticated, ensureVerified, ensureAdmin, function(req, res) {
  var string = encodeURIComponent(req.body.id);
  Contact.findOneAndDelete({ _id: string }, function (err) {
    if(err) console.log(err);
    req.flash('success_msg' , 'requested contact submission has been deleted from database');
        res.redirect('/user/admin');
  });
});





// CallerID Page
router.get("/apps/callerid", ensureAuthenticated, ensureVerified, ensureAdmin, function(req, res) {
  res.render("callerid", { title: "Caller ID Test", user: req.user });
});



// Caller ID check POST request
router.post('/apps/callerid' , ensureAuthenticated, ensureVerified, ensureAdmin, function(req, res){

  if(req.body.number.length != 10 || isNaN(req.body.number)) {
    req.flash('error_msg' , 'Entered number is invalid. Please verify the format.');
    res.redirect('/user/apps/callerid');
  } 
  else {


  var headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': process.env.TELNYX_AUTHORIZATION
};

var options = {
  url: 'https://api.telnyx.com/v2/number_lookup/+1' + req.body.number + '?type=carrier&type=caller-name',
  method: 'GET',
  headers: headers,
};

function callback(error, response, body) {
  var details = JSON.parse(body);
  if (!error && response.statusCode == 200) {
    res.render('callerid', {
      user: req.user,
         details: details,
          title: "Caller ID Test"
    });
  }
}
request(options, callback);
  }
});




// Multi- Factor Authentcation page - GET request
router.get('/mfa', ensureAuthenticated, ensureVerified, (req, res) =>{

  if(!req.user.totp_status){
    res.render("mfa", { title: "Multi-factor Authentication", user: req.user});
  } else {
  qrcode.toDataURL(req.user.totp_otpauth_url, function(err, data){
  
    res.render("mfa", { title: "Multi-factor Authentication", user: req.user, data });
  })
 }
})





// MULTER - Configuration
let profile_picture_id = uuidv4();

var storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, '/home/arth/arthnpatel.com/public/usercontent')
  },
  filename: function (req, file, cb) {
    cb(null, profile_picture_id + '-' +  Math.floor(new Date().getTime() / 1000) + '.jpg');
  }
})

var upload = multer({ storage: storage })

// Profile Upload - POST request
router.post('/profile-upload', ensureAuthenticated, ensureVerified, upload.single('photo'), (req, res) => {  
  upload.single('photo');
  if(!req.file) {
    req.flash('error_msg' , 'Please select a new profile picture to proceed with the change.')
      res.redirect('/user/profile');
  } else {
    if(req.file.size > 2097152){
      req.flash('error_msg' , 'Change failed. Image file size must be less than 2MB.')
      res.redirect('/user/profile');
    }else {
     if(req.file.mimetype == 'image/png' || req.file.mimetype == 'image/jpg' || req.file.mimetype == 'image/jpeg') {
      var conditions = {_id : req.user._id}
      var profile_picture = { "profile_picture" : profile_picture_id + '-' + Math.floor(new Date().getTime() / 1000) + '.jpg'};
      User.update(conditions, profile_picture)
      .then(doc => {
        if(!doc) { return res.status(404).end();}
        else {
          req.flash('success_msg' , 'Success, your profile picture has been changed.')
      res.redirect('/user/profile');
        };
      })
      .catch( err => {
        console.log(err);
        console.log('there is some error');
      });		
     } else {
      req.flash('error_msg' , 'Change failed. Image file must have an extension of JPEG, JPG, or PNG.')
      res.redirect('/user/profile');
          	
     }
    };
  }
});




// Donation page - GET request
router.get('/donation', (req, res) => {
  res.render('donation', {title: "User Donation", user: req.user, payment: ''})
});



// Donation page - POST request
router.post('/donation/create',ensureAuthenticated, ensureVerified, (req, res) => {

  if(!req.body.amount) {
    req.flash('error_msg' , 'Error, please enter a donation value.')
    res.redirect('/user/donation');
  } else {

//build PayPal payment request
var payReq = JSON.stringify({
  'intent':'sale',
  'redirect_urls':{
      'return_url':'http://10.0.0.187:3000/user/donation/process',
      'cancel_url':'http://10.0.0.187:3000/user/donation/cancel'
  },
  'payer':{
      'payment_method':'paypal'
  },
  'transactions':[{
      'amount':{
          'total':req.body.amount,
          'currency':'USD'
      },
      'description':'Donation to Arth Patel.'
  }]
});

paypal.payment.create(payReq, function(error, payment){
  if(error){
      console.error(error);
  } else {
      //capture HATEOAS links
      var links = {};
      payment.links.forEach(function(linkObj){
          links[linkObj.rel] = {
              'href': linkObj.href,
              'method': linkObj.method
          };
      })
  
      //if redirect url present, redirect user
      if (links.hasOwnProperty('approval_url')){
          res.redirect(links['approval_url'].href);
      } else {
          console.error('no redirect URI present');
      }
  }
});

  }
 
});


router.get('/donation/process',ensureAuthenticated, ensureVerified, function(req, res){
  var paymentId = req.query.paymentId;
  var payerId = { 'payer_id': req.query.PayerID };

  paypal.payment.execute(paymentId, payerId, function(error, payment){
      if(error){
          console.error(error);
      } else {
          if (payment.state == 'approved'){ 


          var donationDetails = {
            "local_user_id": req.user._id,
            "payment_id": payment.id,
            "payment_method": payment.payer.payment_method,
            "payer_id": payment.payer.payer_info.payer_id,
            "payer_first_name": payment.payer.payer_info.first_name,
            "payer_last_name": payment.payer.payer_info.last_name,
            "payer_email": payment.payer.payer_info.email,
            "payer_address_fullName": payment.payer.payer_info.shipping_address.recipient_name,
            "payer_shipping_line1": payment.payer.payer_info.shipping_address.line1,
            "payer_shipping_city": payment.payer.payer_info.shipping_address.city,
            "payer_shipping_state": payment.payer.payer_info.shipping_address.state,
            "payer_shipping_postal_code": payment.payer.payer_info.shipping_address.postal_code,
            "payer_shipping_country_code": payment.payer.payer_info.shipping_address.country_code,
            "payer_payment_currency": payment.transactions[0].amount.currency,
            "payer_payment_amount": payment.transactions[0].amount.total,
            "payment_status": 'Approved and Accepted'
          }

          // Saving details to database
          var donationData = new Donation(donationDetails);
          donationData.save()
        .then(item => {
          console.log("item saved to database");
        })
        .catch(err => {
          req.flash('error_msg' , 'Error, payment via Paypal was unsuccessful. Please try again later.');
            res.redirect('/user/donation');
        });

          // Getting first name from full name
          var fName  = req.user.name.split(" "),
      firstName = fName.shift()


            // Sending a confirmation email using Mailgun
            mailgun.messages().send({
              from: 'Arth Patel <accounts@arthnpatel.com>',
              to: req.body.email,
              //bcc: 'arth@arthnpatel.com',
              subject: 'Thank you for your generous donation.',
              text: 'Dear ' + firstName + ',\n\n' +
              'Thank you for your gift of $ ' + payment.transactions[0].amount.total + '.' + ' Convoy of Hope has deployed trucks and teams to myself, Arth Patel. Our prayers go out to the Asian families in Atlanta who lost loved ones, homes and businesses. Because of friends like you, your donation was able to immediately assist in education of asian student, including myself who have immigrated to the United States solely for the purpose of upbringing our community in terms of technology and innovation. Thank you!\n\n' +
              'With your help, we will reach even more families and children in need here at home and around the world this year.\n\n' +
              'Below is a summary of your gift. You can also access a receipt online by clicking on this link: ' + 'https://arthnpatel.com/user/recent-donations\n\n' +
              'Transaction date: ' + new Date() + '\n' +
              'Amount: ' + payment.transactions[0].amount.total + ' ' + payment.transactions[0].amount.currency + '\n' +
              'Designation: ' + 'Donation to further education for Arth Patel\n\n' +
              'Thank you for your compassion.\n\n' +
              'Sincerely,\n\n' +
              'Arth Patel, https://arthnpatel.com'
            }).
            then(res => console.log(res)).
            catch(err => console.err(err));

          // Sending the confirmation email ends here




        req.flash('success_msg' , 'We have received your donation of ' + payment.transactions[0].amount.total + ' ' + payment.transactions[0].amount.currency + ' successfully. We appreciate your trust and support. Please find the transaction details under Past Donations tab on your dashboard. A confirmation email was just sent to the email associated with your account.');
        res.redirect('/user/donation');


          } else {

            req.flash('error_msg' , 'Error, payment via Paypal was unsuccessful. Please try again later.');
            res.redirect('/user/donation');
          }
      }
  });
});



// Recent donations - GET request
router.get('/recent-donations', ensureAuthenticated,ensureVerified, function(req, res) {
  
  var user = req.user._id;
      User.find({_id: user}, function(err, user) {
        if (err) {
          res.send(err);
        } else {
          if(user[0].adminAccount) {


            Donation.find({}, function(err, donationlist) {
              if (err) {
                res.send(err);
              } else {
                let sortedInput = donationlist.slice().sort((a, b) => b.date - a.date);
                let result  = sortedInput;
                res.render('recent-donations', {
                  user: req.user,
                  result,
                  title: "Recent Donations"
                });
              }
            });

          } else {

            var user = req.user.id;
            Donation.find({local_user_id: user}, function(err, donationlist) {
              if (err) {
                res.send(err);
              } else {
                let sortedInput = donationlist.slice().sort((a, b) => b.date - a.date);
                let result  = sortedInput;
                res.render('recent-donations', {
                  user: req.user,
                  result,
                  title: "Recent Donations"
                });
              }
            });

          }
        }
      });
    
});



// User log in history

router.get('/login-history', ensureAuthenticated, ensureVerified, function(req, res, next) {
  res.redirect('/user/login-history/1');
})


router.get('/login-history/:page',ensureAuthenticated, ensureVerified, function(req, res, next) {



  var perPage = 15
  var page = req.params.page || 1

  LoginHistory
      .find({userEmail: req.user.email})
      .sort('-date')
      .skip((perPage * page) - perPage)
      .limit(perPage)
      .exec(function(err, loginHistory) {
        let count1 = Object.keys(loginHistory).length
            if (err) return next(err)
            LoginHistory.find({userEmail: req.user.email}, function(err, totaluserlogindataarray) {
                let count = Object.keys(totaluserlogindataarray).length
              res.render('login-history', {
                  login: loginHistory,
                  current: page, // Current page number
                  perPage,
                  count,
                  count1,
                  pages: Math.ceil(count / perPage),
                  title: 'Login History',
                  user: req.user
              })
          })
        })
})




module.exports = router;
