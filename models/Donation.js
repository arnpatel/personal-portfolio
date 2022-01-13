const mongoose = require('mongoose');


const UserSchema = new mongoose.Schema({
    
    date: {
        type: Date,
        default: Date.now
    },
    local_user_id: {
        type: String,
        required: true
    },
    payment_id: {
        type: String,
        required: true
    },
    payment_method: {
        type: String,
        required: true
    },
    payer_id: {
        type: String,
        required: true
    },
    payer_first_name: {
        type: String,
        required: true
    },
    payer_last_name: {
        type: String,
        required: true
    },
    payer_email: {
        type: String,
        required: true
    },
    payer_address_fullName: {
        type: String,
        required: true
    },
    payer_shipping_line1: {
        type: String,
        required: true
    },
    payer_shipping_city: {
        type: String,
        required: true
    },
    payer_shipping_state: {
        type: String,
        required: true
    },
    payer_shipping_postal_code: {
        type: String,
        required: true
    },
    payer_shipping_country_code: {
        type: String,
        required: true
    },
    payer_payment_currency: {
        type: String,
        required: true
    },
    payer_payment_amount: {
        type: String,
        required: true
    },
    payment_status: {
        type: String,
        required: true
    },

  });
  
  const Donation = mongoose.model('Donation', UserSchema);
  
  module.exports = Donation;