const { deserializeUser } = require("passport");

module.exports = {
  ensureAuthenticated: function(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    req.flash('error_msg', 'Please log in to view the requested resource.');
    res.redirect('/auth/login?continue=' +  req.originalUrl + '&entry=SecureLogin&api=AP-Technologies');
  },
  forwardAuthenticated: function(req, res, next) {
    if (!req.isAuthenticated()) {
      return next();
    }
    res.redirect('/user/dashboard');      
  },
  ensureVerified: function(req, res, next) {
    if(req.user.verified === 'true'){
      return next();
    }
      req.flash('error_msg', 'Your account is not verified');
      res.redirect('/auth/email-verification');
  },
  ensureAdmin: function(req, res, next) {
    if(req.user.adminAccount=== 'true'){
      return next();
    }
      req.flash('error_msg', 'Access denied.');
      res.redirect('/user/dashboard');
  }
};
