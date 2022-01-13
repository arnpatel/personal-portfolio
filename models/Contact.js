const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  submission_id: {
    type: String,
    required: true
  },
  ip: {
    type: String,
    required: true
  },
  latitude: {
    type: String,
    required: true
  },
  longitude: {
    type: String,
    required: true
  },
  city: {
    type: String,
    required: true
  },
  region: {
    type: String,
    required: true
  },
  country_name: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  subject: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  },
  notes: {
    type: String,
    required: true
  },
  notesDate: {
    type: String
  },
  last_updated_by: {
    type: String,
    required: true
  },
  score: {
    type: String,
    required: true
  }
});

const Contact = mongoose.model('Contact', UserSchema);

module.exports = Contact;
