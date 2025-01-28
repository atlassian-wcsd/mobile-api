const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { encrypt } = require('../utils/encryption');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  mfaEnabled: {
    type: Boolean,
    default: false
  },
  tempMFAToken: {
    type: String,
    default: null
  },
  resetPasswordToken: {
    type: String,
    default: null
  },
  resetPasswordExpires: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  lastLogin: {
    type: Date
  },
  securityQuestions: [{
    question: String,
    answer: String // Stored encrypted
  }],
  status: {
    type: String,
    enum: ['active', 'inactive', 'locked'],
    default: 'active'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for performance optimization
userSchema.index({ email: 1 });
userSchema.index({ resetPasswordToken: 1, resetPasswordExpires: 1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Pre-save middleware to encrypt security question answers
userSchema.pre('save', async function(next) {
  if (this.isModified('securityQuestions')) {
    this.securityQuestions = this.securityQuestions.map(qa => ({
      question: qa.question,
      answer: encrypt(qa.answer.toLowerCase())
    }));
  }
  next();
});

// Instance method to check if account is locked
userSchema.methods.isLocked = function() {
  return this.lockUntil && this.lockUntil > Date.now();
};

// Instance method to increment login attempts
userSchema.methods.incrementLoginAttempts = async function() {
  const maxAttempts = 5;
  const lockTime = 30 * 60 * 1000; // 30 minutes

  // Reset attempts if lock has expired
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.loginAttempts = 1;
    this.lockUntil = null;
  } else {
    this.loginAttempts += 1;
    
    // Lock account if max attempts reached
    if (this.loginAttempts >= maxAttempts) {
      this.lockUntil = Date.now() + lockTime;
      this.status = 'locked';
    }
  }

  return this.save();
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = async function() {
  this.loginAttempts = 0;
  this.lockUntil = null;
  this.status = 'active';
  return this.save();
};

// Instance method to update last login
userSchema.methods.updateLastLogin = async function() {
  this.lastLogin = new Date();
  return this.save();
};

// Static method to find user by email (case insensitive)
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

// Virtual for user's full security status
userSchema.virtual('securityStatus').get(function() {
  return {
    mfaEnabled: this.mfaEnabled,
    accountLocked: this.isLocked(),
    status: this.status,
    lastLogin: this.lastLogin
  };
});

const User = mongoose.model('User', userSchema);

module.exports = User;