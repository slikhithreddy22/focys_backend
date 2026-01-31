import AccessControl from '../models/AccessControl.js';

// Check if user has permission for specific action
export const checkPermission = (object, action) => {
  return async (req, res, next) => {
    try {
      // Make sure user exists
      if (!req.user || !req.user.role) {
        return res.status(401).json({ 
          message: 'Authentication required'
        });
      }

      const userRole = req.user.role;

      // Find access control rules for this role and object
      const accessRule = await AccessControl.findOne({
        subject: userRole,
        object: object
      });

      if (!accessRule) {
        console.log(`No access rule found for role: ${userRole}, object: ${object}`);
        return res.status(403).json({ 
          message: 'Access denied: No access rules defined for your role',
          requiredPermission: action,
          object: object
        });
      }

      // Check if user has required permission
      if (!accessRule.permissions.includes(action)) {
        console.log(`Permission denied - Role: ${userRole}, Action: ${action}, Object: ${object}`);
        return res.status(403).json({ 
          message: `Access denied: You don't have '${action}' permission for ${object}`,
          yourPermissions: accessRule.permissions
        });
      }

      next();
    } catch (error) {
      console.error('Access control error:', error);
      res.status(500).json({ 
        message: 'Error checking permissions',
        error: error.message 
      });
    }
  };
};

// Initialize default access control rules
export const initializeAccessControl = async () => {
  try {
    const defaultRules = [
      // Admin permissions
      {
        subject: 'admin',
        object: 'contacts',
        permissions: ['create', 'read', 'update', 'delete', 'manage']
      },
      {
        subject: 'admin',
        object: 'users',
        permissions: ['create', 'read', 'update', 'delete', 'manage']
      },
      {
        subject: 'admin',
        object: 'settings',
        permissions: ['create', 'read', 'update', 'delete', 'manage']
      },
      // Manager permissions
      {
        subject: 'manager',
        object: 'contacts',
        permissions: ['create', 'read', 'update', 'delete']
      },
      {
        subject: 'manager',
        object: 'users',
        permissions: ['read', 'update']
      },
      {
        subject: 'manager',
        object: 'settings',
        permissions: ['read']
      },
      // User permissions
      {
        subject: 'user',
        object: 'contacts',
        permissions: ['create', 'read']
      },
      {
        subject: 'user',
        object: 'users',
        permissions: ['read']
      },
      {
        subject: 'user',
        object: 'settings',
        permissions: ['read']
      }
    ];

    for (const rule of defaultRules) {
      await AccessControl.findOneAndUpdate(
        { subject: rule.subject, object: rule.object },
        rule,
        { upsert: true, new: true }
      );
    }

    console.log('✅ Access control rules initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing access control:', error);
  }
};