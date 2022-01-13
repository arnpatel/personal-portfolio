const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  strategy: {
    type: String,
    required: true
  },
  name: {
    type: String,
  },
  googleId: {
    type: String,
  },
  githubId: {
    type: String,
  },
  githubUsername: {
    type: String,
  },
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
  },
  date: {
    type: Date,
    default: Date.now
  },
  registrationVerification: String,
  verified: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  status: {
    type: String,
  },
  totp_secret: {
    type: String,
  },
  totp_status: {
    type: String,
  },
  totp_otpauth_url: {
    type: String,
  },
  totp_enrolment_date: {
    type: Date,
    default: Date.now
  },
  profile_picture: {
    type: String,
  },
  oauth_profile_picture: {
    type: String,
  },
  provider: {
    type: String,
  },
  adminAccount: {
    type: String,
  },
  totp_iv: {
    type: String,
  },
  totp_login_password: {
    type: String,
  },
  totp_iv_expiry: {
    type: String,
  },
  last_login: {
    type: String,
  },
  last_login_ip: {
    type: String,
  }
});

const User = mongoose.model('User', UserSchema);

module.exports = User;
