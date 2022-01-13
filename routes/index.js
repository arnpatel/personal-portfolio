const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
var fs = require('file-system');
const request = require('request');
const methodOverride = require("method-override");
// Load User and Contact model
const User = require('../models/User');
const Contact = require('../models/Contact');
const { ensureAdmin, ensureAuthenticated} = require('../config/auth');
const {v4 : uuidv4} = require('uuid');
const rateLimit = require("express-rate-limit");

var app = express();






// Rate limiting Authentication routes.
const limiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 100 requests per windowMs,
  message: 'Error 429 (Too Many Requests): <br/><br/> Halt your horses, you exceeded the rate limit momentarily. Try accesing the route again in half an hour. <br/><br/> Sincerely, <br/> AP Technologies'
});



// Mailgun variable initialization
var apiKey = process.env.MAILGUN_PRIVATE_KEY;
var domain = 'arthnpatel.com';
const mailgun = require('mailgun-js')({ domain, apiKey });



//Math Problem for email verification
  function X(min, max) {  
    return Math.floor(
      Math.random() * (max - min + 1) + min
    )
  }
  function Y(min, max) {  
    return Math.floor(
      Math.random() * (max - min + 1) + min
    )
  }

// Index Page
router.get("/", function(req, res) {
  var xNumber = X(1,50);
    var yNumber = Y(1,50);
  
  res.render("index", { title: "", user: req.user, xNumber, yNumber});
});

// About Me
router.get("/about", function(req, res) { 
  res.render("about", { title: "About Me", user: req.user });
});

// Blog Main Page
router.get("/blog", function(req, res) {
  res.render("blog", { title: "Blog", user: req.user });
});


// Contact Me
router.get("/contact", function(req, res) { 
  res.render("contact", { title: "Contact Me", user: req.user });
});

// Blog Post No. 1 - Pritunl
router.get("/blog/creating-my-own-secure-vpn-using-pritunl", function(req, res) { 
  res.render("blog-1", { title: "Creating my own secure VPN using Pritunl", user: req.user });
});

// Blog Post No. 2 - Programming project this summer.
router.get("/blog/programming-project-this-confined-summer", function(req, res) {
  res.render("blog-2", { title: "Programming project this confined summer.", user: req.user });
});

// Blog Post No. 3 - Theoretically calculating subnet mask for network management..
router.get("/blog/calculating-subnet-masks-for-network-management", function(req, res) {
  res.render("blog-3", { title: "Calculating subnet masks for network management.", user: req.user });
});


// Redirect - AP Contact
router.get("/apc", function(req, res) { 
  res.redirect(301, "https://sheltered-oasis-38500.herokuapp.com/");
});

// Redirect - Zoho Mail
router.get("/mail", function(req, res) { 
  res.redirect(301, "http://autodiscover.arthnpatel.com");
});



// Contact Page - POST handling
router.post('/contact', limiter, [

  check('name','Full name must be between 4 and 20 chars').isLength({ min: 4, max:20 }),
  check('email','Email must be in format xyz@arthnpatel.com').isEmail(),
  check('subject','Subject must be between 5 and 30 chars').isLength({ min: 5, max:30 }),
  check('message','Message must be between 5 and 255 chars').isLength({ min: 5, max:255 })

], function(req, res){


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
          req.flash('error_msg' , 'Submission denied. You seem to be misusing the contact form, try again later.')
          res.redirect('/contact');
        } else {
   

    const errors = validationResult(req);
    
    if(!errors.isEmpty()){
      const alert = errors.array()
      const error1 = alert[0];
      const error2 = alert [1];
      const error3 = alert [2];
      const error4 = alert[3];
      res.render('contact', {title: "Contact Me", alert, user: req.user, error1, error2, error3, error4})

    
    }
    else {
      // Saving user entered details to the DB with user's geo location.
      // generate reference number
      let submission_id = uuidv4();
      let notes = "Received";
      let lastUpdatedBy = "system API";
      app.set('trust proxy', true);
      var ipAddress = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      let URL = "https://www.ipapi.co/" + ipAddress + "/json";
      request({
        url: URL,
        json: true
      }, (err, response, body) => {
          if(!err && response.statusCode == 200){
        let location = body;
      var contactDetails = {"submission_id": submission_id, "ip": location.ip,"latitude": location.latitude,"longitude": location.longitude, "city":location.city, "region":location.region, "country_name": location.country_name, "name":req.body.name, "email":req.body.email, "subject":req.body.subject, "message":req.body.message, "notes": notes, "last_updated_by": lastUpdatedBy, "score": recaptcha.score};
      var contactData = new Contact(contactDetails);
      contactData.save()
        .then(item => {
          res.send("item saved to database");
        })
        .catch(err => {
          res.status(400).send("unable to save to database");
        });

        // Sending User and I the confirmation email.
      let formSubmission = "the message is processed successfully";

      // Getting first name from the full name
      var fName  = req.body.name.split(" "),
      firstName = fName.shift()


      // SEND THE CONFIRMATION EMAIL// 

      mailgun.messages().send({
        from: 'Arth Patel <accounts@arthnpatel.com>',
        to: req.body.email,
        subject: "We have received your contact form submission.",
        text: 'Hi ' + firstName + ',\n\n' +
        'This is a confirmation email for submission made on the contact form located at arthnpatel.com/contact. Submission details are as below:\n\n' +
        'Date/Time: ' + new Date() + '\n' +
        'Reference Number: ' + submission_id + '\n' +
        'Location: ' + location.city + ", " + location.region + '\n' +
        'Country: ' + location.country_name + '\n\n' +
        'Name: ' + req.body.name + '\n' +
        'Email: ' + req.body.email + '\n' +
        'Subject: ' + req.body.subject + '\n' +
        'Message: ' + '\n' +
        req.body.message + '\n\n' +
        'Best,\n' +
        'Arth Patel\n\n' +
        'Note: This is an unmonitored mailbox. Write all questions to arth@arthnpatel.com.'
      }).
      then(res => console.log(res)).
      catch(err => console.err(err));

      // The process for sending confirmation email ends here.

  res.render('contact',{title: "Contact Me", formSubmission, req, user: req.user, firstName})
    }
  });


}}
}
);
});




router.use(methodOverride("_method", {
  methods: ["POST", "GET"]
}));


// Update contact form notes
router.put('/contact/notes/update/:id', ensureAdmin, ensureAuthenticated, function(req, res) {
  var token = encodeURIComponent(req.params.id);
  var conditions = {_id: req.params.id};
  var cDate = new Date().toLocaleString();
  var changes = {"notes": req.body.notes, "notesDate": cDate, "last_updated_by": req.user.email}
  if(req.body.notes.length < 1){
    req.flash('error_msg' , 'Notes data must be at least 1 characters.')
    res.redirect('/user/admin');
  }
  else {
  Contact.update(conditions, changes)
  .then(doc => {
    if(!doc) { return res.status(404).end();}
    req.flash('success_msg' , 'Success, the requested notes information has been changed.')
    res.redirect('/user/admin');
  })
}
});


// Track contact form submission
router.get("/contact/track-submission", function(req, res) { 
  res.render("trackContactSubmissionStatus", { title: "Track Contact Form Submission", user: req.user });
});



// Track contact form submission POST request
router.post('/contact/track-submission', function(req, res){
  Contact.findOne({ submission_id: req.body.referencenumber}, function(err, contact) {
   if(!contact){
    req.flash('error_msg' , 'This reference number cannot be found, please check the confirmation email.');
    res.redirect('/contact/track-submission');
   } else {
    Contact.find({submission_id: req.body.referencenumber }, function(err, result) {
      if (err) {
        res.send(err);
      } else {
        console.log(result);
        res.render('trackContactSubmissionStatus', {
          user: req.user,
          result,
          title: "Track Contact Form Submission"
        });
      }
    });
   }

  });
});




// Resume Link
router.get("/resume/ArthPatel", ensureAuthenticated,function(req, res) {
  var tempFile="/home/arth/arthnpatel.com/resources/ArthPatel.pdf";
  fs.readFile(tempFile, function (err,data){
     res.contentType("application/pdf");
     res.send(data);
  });
});

// ENGR-240 Lab Report 1 Link
router.get("/engr240/report1", ensureAuthenticated,function(req, res) {
  var tempFile="/home/arth/arthnpatel.com/resources/report1.pdf";
  fs.readFile(tempFile, function (err,data){
     res.contentType("application/pdf");
     res.send(data);
  });
});

// ENGR-240 Lab Report 2 Link
router.get("/engr240/report2", ensureAuthenticated,function(req, res) {
  var tempFile="/home/arth/arthnpatel.com/resources/report2.pdf";
  fs.readFile(tempFile, function (err,data){
     res.contentType("application/pdf");
     res.send(data);
  });
});

// Legal page
router.get("/legal", function(req, res) { 
  res.render("legal", { title: "Legal", user: req.user });
});



// Email Spam Prevention - POST request
router.post("/spam-prevention", function(req, res) {

  if(!req.user) {
    req.flash('error_msg' , 'Log in to view my email.');
    res.redirect('/');
  } else {
    if( Number(req.body.xNumber) + Number(req.body.yNumber) != req.body.xy) {
      req.flash('error_msg' , 'Incorrect entry.');
      res.redirect('/');
      
    } else {
      req.flash('success_msg' , 'My email is arth [at] arthnpatel.com. Do not send UCE.');
          res.redirect('/');
    }
  }

});




module.exports = router;
