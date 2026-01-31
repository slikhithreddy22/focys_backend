import express from 'express';
import User from '../models/User.js';
import Contact from '../models/Contact.js';
import AccessControl from '../models/AccessControl.js';
import { protect } from '../middleware/auth.js';
import { checkPermission } from '../middleware/accessControl.js';
const router = express.Router();
// Get all users (admin/manager only)
router.get('/users', protect, checkPermission('users', 'read'), async (req, res) => {
  try {
    const users = await User.find()
      .select('-passwordHash -passwordSalt -mfaSecret')
      .sort({ createdAt: -1 });
    res.json({
      success: true,
      users: users.map(user => ({
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }))
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server error while fetching users' });
  }
});
// Update user role (admin only)
router.put('/users/:id/role', protect, checkPermission('users', 'manage'), async (req, res) => {
  try {
    const { role } = req.body;
    if (!['admin', 'manager', 'user'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    user.role = role;
    await user.save();
    res.json({
      success: true,
      message: 'User role updated successfully',
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Update role error:', error);
    res.status(500).json({ message: 'Server error while updating user role' });
  }
});
// Deactivate/activate user (admin only)
router.put('/users/:id/status', protect, checkPermission('users', 'manage'), async (req, res) => {
  try {
    const { isActive } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    // Prevent self-deactivation
    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'Cannot deactivate your own account' });
    }
    user.isActive = isActive;
    await user.save();
    res.json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
      user: {
        id: user._id,
        username: user.username,
        isActive: user.isActive
      }
    });
  } catch (error) {
    console.error('Update status error:', error);
    res.status(500).json({ message: 'Server error while updating user status' });
  }
});
// Get all contacts (admin only)
router.get('/contacts', protect, checkPermission('contacts', 'manage'), async (req, res) => {
  try {
    const contacts = await Contact.find()
      .populate('sender', 'username email')
      .populate('recipient', 'username email')
      .sort({ createdAt: -1 })
      .limit(50);
    res.json({
      success: true,
      contacts: contacts.map(contact => ({
        id: contact._id,
        sender: contact.sender,
        recipient: contact.recipient,
        subject: contact.subject,
        priority: contact.priority,
        isRead: contact.isRead,
        createdAt: contact.createdAt
      }))
    });
  } catch (error) {
    console.error('Get all contacts error:', error);
    res.status(500).json({ message: 'Server error while fetching contacts' });
  }
});
// Get system statistics (admin only)
router.get('/stats', protect, checkPermission('settings', 'read'), async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const totalContacts = await Contact.countDocuments();
    const unreadContacts = await Contact.countDocuments({ isRead: false });
    const usersByRole = await User.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } }
    ]);
    const contactsByPriority = await Contact.aggregate([
      { $group: { _id: '$priority', count: { $sum: 1 } } }
    ]);
    res.json({
      success: true,
      stats: {
        users: {
          total: totalUsers,
          active: activeUsers,
          byRole: usersByRole
        },
        contacts: {
          total: totalContacts,
          unread: unreadContacts,
          byPriority: contactsByPriority
        }
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ message: 'Server error while fetching statistics' });
  }
});
// Get access control rules
router.get('/access-control', protect, checkPermission('settings', 'read'), async (req, res) => {
  try {
    const rules = await AccessControl.find().sort({ subject: 1, object: 1 });
    res.json({
      success: true,
      accessControlRules: rules
    });
  } catch (error) {
    console.error('Get access control error:', error);
    res.status(500).json({ message: 'Server error while fetching access control rules' });
  }
});
export default router;