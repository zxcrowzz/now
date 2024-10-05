const mongoose = require('mongoose');

const pendingUserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 } // Expires in 1 hour
});

module.exports = mongoose.model('PendingUser', pendingUserSchema);