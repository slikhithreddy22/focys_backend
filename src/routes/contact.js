import express from 'express';
import Contact from '../models/Contact.js';
import User from '../models/User.js';
import { protect } from '../middleware/auth.js';
import { checkPermission } from '../middleware/accessControl.js';
import { encrypt, decrypt } from '../utils/encryption.js';
import { createSimpleSignature, verifySimpleSignature } from '../utils/digitalSignature.js';
import { generateQRCode, encodeBase64 } from '../utils/encoding.js';
import { sendContactNotification } from '../utils/emailService.js';

const router = express.Router();

// Send contact form
router.post('/send', protect, checkPermission('contacts', 'create'), async (req, res) => {
  try {
    const { recipientId, subject, message, priority } = req.body;

    if (!recipientId || !subject || !message) {
      return res.status(400).json({ message: 'Please provide all required fields' });
    }

    // Get recipient
    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({ message: 'Recipient not found' });
    }

    // Encrypt message
    const { encryptedData, iv } = encrypt(message);

    // Create digital signature and hash
    const { signature, hash } = createSimpleSignature(message, process.env.JWT_SECRET);

    // Generate QR code for contact form ID (will be updated after creation)
    const contactData = {
      sender: req.user.username,
      recipient: recipient.username,
      subject,
      timestamp: new Date().toISOString()
    };

    const qrCode = await generateQRCode(JSON.stringify(contactData));

    // Create contact
    const contact = await Contact.create({
      sender: req.user._id,
      recipient: recipientId,
      subject,
      encryptedMessage: encryptedData,
      iv,
      digitalSignature: signature,
      messageHash: hash,
      qrCode,
      priority: priority || 'medium'
    });

    // Send email notification to recipient
    await sendContactNotification(recipient.email, req.user.username, subject);

    res.status(201).json({
      success: true,
      message: 'Contact form sent successfully',
      contact: {
        id: contact._id,
        recipient: recipient.username,
        subject: contact.subject,
        priority: contact.priority,
        createdAt: contact.createdAt
      }
    });
  } catch (error) {
    console.error('Send contact error:', error);
    res.status(500).json({ message: 'Server error while sending contact form' });
  }
});

// Get received contacts
router.get('/received', protect, checkPermission('contacts', 'read'), async (req, res) => {
  try {
    const { page = 1, limit = 10, unreadOnly = false } = req.query;

    const query = { recipient: req.user._id };
    if (unreadOnly === 'true') {
      query.isRead = false;
    }

    const contacts = await Contact.find(query)
      .populate('sender', 'username email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const count = await Contact.countDocuments(query);

    res.json({
      success: true,
      contacts: contacts.map(contact => ({
        id: contact._id,
        sender: contact.sender,
        subject: contact.subject,
        priority: contact.priority,
        isRead: contact.isRead,
        readAt: contact.readAt,
        createdAt: contact.createdAt,
        qrCode: contact.qrCode
      })),
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      totalContacts: count
    });
  } catch (error) {
    console.error('Get contacts error:', error);
    res.status(500).json({ message: 'Server error while fetching contacts' });
  }
});

// Get sent contacts
router.get('/sent', protect, checkPermission('contacts', 'read'), async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;

    const contacts = await Contact.find({ sender: req.user._id })
      .populate('recipient', 'username email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const count = await Contact.countDocuments({ sender: req.user._id });

    res.json({
      success: true,
      contacts: contacts.map(contact => ({
        id: contact._id,
        recipient: contact.recipient,
        subject: contact.subject,
        priority: contact.priority,
        isRead: contact.isRead,
        readAt: contact.readAt,
        createdAt: contact.createdAt
      })),
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      totalContacts: count
    });
  } catch (error) {
    console.error('Get sent contacts error:', error);
    res.status(500).json({ message: 'Server error while fetching sent contacts' });
  }
});

// Get specific contact and decrypt
router.get('/:id', protect, checkPermission('contacts', 'read'), async (req, res) => {
  try {
    const contact = await Contact.findById(req.params.id)
      .populate('sender', 'username email')
      .populate('recipient', 'username email');

    if (!contact) {
      return res.status(404).json({ message: 'Contact not found' });
    }

    // Check if user is sender or recipient
    if (
      contact.sender._id.toString() !== req.user._id.toString() &&
      contact.recipient._id.toString() !== req.user._id.toString()
    ) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Decrypt message
    const decryptedMessage = decrypt(contact.encryptedMessage, contact.iv);

    // Verify digital signature
    const isValid = verifySimpleSignature(
      decryptedMessage,
      contact.digitalSignature,
      process.env.JWT_SECRET,
      contact.messageHash
    );

    // Mark as read if recipient is viewing
    if (contact.recipient._id.toString() === req.user._id.toString() && !contact.isRead) {
      contact.isRead = true;
      contact.readAt = new Date();
      await contact.save();
    }

    res.json({
      success: true,
      contact: {
        id: contact._id,
        sender: contact.sender,
        recipient: contact.recipient,
        subject: contact.subject,
        message: decryptedMessage,
        priority: contact.priority,
        isRead: contact.isRead,
        readAt: contact.readAt,
        createdAt: contact.createdAt,
        qrCode: contact.qrCode,
        signatureValid: isValid,
        messageHash: contact.messageHash
      }
    });
  } catch (error) {
    console.error('Get contact error:', error);
    res.status(500).json({ message: 'Server error while fetching contact' });
  }
});

// Delete contact
router.delete('/:id', protect, checkPermission('contacts', 'delete'), async (req, res) => {
  try {
    const contact = await Contact.findById(req.params.id);

    if (!contact) {
      return res.status(404).json({ message: 'Contact not found' });
    }

    // Check if user is sender or recipient (or admin)
    if (
      contact.sender.toString() !== req.user._id.toString() &&
      contact.recipient.toString() !== req.user._id.toString() &&
      req.user.role !== 'admin'
    ) {
      return res.status(403).json({ message: 'Access denied' });
    }

    await contact.deleteOne();

    res.json({
      success: true,
      message: 'Contact deleted successfully'
    });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({ message: 'Server error while deleting contact' });
  }
});

// Get contact statistics
router.get('/stats/summary', protect, checkPermission('contacts', 'read'), async (req, res) => {
  try {
    const sent = await Contact.countDocuments({ sender: req.user._id });
    const received = await Contact.countDocuments({ recipient: req.user._id });
    const unread = await Contact.countDocuments({ recipient: req.user._id, isRead: false });

    res.json({
      success: true,
      stats: {
        sent,
        received,
        unread
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ message: 'Server error while fetching statistics' });
  }
});

export default router;
