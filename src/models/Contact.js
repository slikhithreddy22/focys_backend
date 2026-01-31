import mongoose from 'mongoose';

const contactSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  subject: {
    type: String,
    required: true,
    maxlength: 200
  },
  encryptedMessage: {
    type: String,
    required: true
  },
  iv: {
    type: String,
    required: true
  },
  digitalSignature: {
    type: String,
    required: true
  },
  messageHash: {
    type: String,
    required: true
  },
  qrCode: {
    type: String,
    default: null
  },
  isRead: {
    type: Boolean,
    default: false
  },
  readAt: {
    type: Date,
    default: null
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  }
}, {
  timestamps: true
});

export default mongoose.model('Contact', contactSchema);