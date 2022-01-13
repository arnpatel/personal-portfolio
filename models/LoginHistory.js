const mongoose = require('mongoose');


const UserSchema = new mongoose.Schema({
    
    userEmail: {
        type: String,
    required: true
    },
    date: {
        type: Date,
        default: Date.now
    },
    ipAddress: {
        type: String,
    required: true
    },
    created: {
        type: Date,
        default: Date.now
      },
  });

  UserSchema.index({createdAt: 1},{expireAfterSeconds: 259200});
  
  const LoginHistory = mongoose.model('LoginHistory', UserSchema);
  
  module.exports = LoginHistory;