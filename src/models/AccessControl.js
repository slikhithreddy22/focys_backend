import mongoose from 'mongoose';

const accessControlSchema = new mongoose.Schema({
  subject: {
    type: String,
    required: true,
    enum: ['admin', 'manager', 'user']
  },
  object: {
    type: String,
    required: true,
    enum: ['contacts', 'users', 'settings']
  },
  permissions: [{
    type: String,
    enum: ['create', 'read', 'update', 'delete', 'manage']
  }]
}, {
  timestamps: true
});

// Create unique index
accessControlSchema.index({ subject: 1, object: 1 }, { unique: true });

export default mongoose.model('AccessControl', accessControlSchema);