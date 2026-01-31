import express from 'express';
import speakeasy from 'speakeasy';

import User from '../models/User.js';
import { generateSalt, hashPassword, verifyPassword } from '../utils/hashing.js';
import { generateToken, protect } from '../middleware/auth.js';
import { sendOTPEmail } from '../utils/emailService.js';
import { generateKeyPair } from '../utils/encryption.js';
import { generateQRCode } from '../utils/encoding.js';

const router = express.Router();

/**
 * Temporary in-memory OTP store
 * NOTE: In production, use Redis or database
 */
const otpStore = new Map();

/* ======================================================
   REGISTER USER
   ====================================================== */
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    /* ---- Validation ---- */
    if (!username || !email || !password) {
      return res.status(400).json({
        message: 'Please provide all required fields'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters long'
      });
    }

    /* ---- Check Existing User ---- */
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        message: 'User already exists'
      });
    }

    /* ---- Password Hashing ---- */
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);

    /* ---- RSA Key Pair ---- */
    const { publicKey, privateKey } = generateKeyPair();

    /* ---- Create User ---- */
    const user = await User.create({
      username,
      email,
      passwordHash,
      passwordSalt: salt,
      role: role || 'user',
      publicKey
    });

    /* ---- JWT Token ---- */
    const token = generateToken(user._id);

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        publicKey: user.publicKey
      },
      privateKey // Sent ONCE – user must store securely
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      message: 'Server error during registration'
    });
  }
});

/* ======================================================
   LOGIN – STEP 1 (PASSWORD VERIFICATION)
   ====================================================== */
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        message: 'Please provide username and password'
      });
    }

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    /* ---- Account Lock Check ---- */
    if (user.isLocked) {
      const minutesLeft = Math.ceil(
        (user.lockUntil - Date.now()) / (1000 * 60)
      );

      return res.status(423).json({
        message: `Account locked. Try again in ${minutesLeft} minutes`
      });
    }

    /* ---- Verify Password ---- */
    const isValid = await verifyPassword(
      password,
      user.passwordSalt,
      user.passwordHash
    );

    if (!isValid) {
      user.loginAttempts += 1;

      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
        await user.save();

        return res.status(423).json({
          message: 'Account locked due to too many failed attempts'
        });
      }

      await user.save();
      return res.status(401).json({
        message: 'Invalid credentials',
        attemptsRemaining: 5 - user.loginAttempts
      });
    }

    /* ---- Reset Attempts ---- */
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    // Optional 2-step verification:
    // - If enabled, use Authenticator-app TOTP (changes every ~30 seconds)
    // - If not enabled, complete login after single-factor password verification
    if (user.mfaEnabled && user.mfaSecret) {
      return res.json({
        success: true,
        message: 'Password verified. Enter your authenticator code.',
        userId: user._id,
        requiresMFA: true,
        mfaType: 'totp'
      });
    }

    // Single-factor login success
    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user._id);

    return res.json({
      success: true,
      message: 'Login successful',
      token,
      user: await User.findById(user._id).select('-passwordHash -passwordSalt')
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      message: 'Server error during login'
    });
  }
});

/* ======================================================
   LOGIN – STEP 2 (OTP VERIFICATION)
   ====================================================== */
router.post('/verify-otp', async (req, res) => {
  try {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
      return res.status(400).json({
        message: 'UserId and OTP are required'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    // If authenticator MFA is enabled, verify TOTP against the user's stored secret.
    if (user.mfaEnabled && user.mfaSecret) {
      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: String(otp),
        step: 30,
        window: 2
      });

      if (!verified) {
        return res.status(401).json({
          message: 'Invalid authenticator code'
        });
      }

      // Success -> issue token
      user.lastLogin = new Date();
      await user.save();

      const token = generateToken(user._id);

      return res.json({
        success: true,
        message: 'Login successful',
        token,
        user: await User.findById(userId).select('-passwordHash -passwordSalt')
      });
    }

    // If MFA is not enabled, this endpoint should not be used.
    return res.status(400).json({
      message: '2-step verification is not enabled for this account'
    });

    safeUser.lastLogin = new Date();
    await safeUser.save();

    const token = generateToken(safeUser._id);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: safeUser
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({
      message: 'Server error during OTP verification'
    });
  }
});

/* ======================================================
   RESEND OTP
   ====================================================== */
router.post('/resend-otp', async (req, res) => {
  try {
    const { userId } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    const otp = speakeasy.totp({
      secret: process.env.JWT_SECRET + user._id,
      encoding: 'base32',
      step: 300
    });

    otpStore.set(user._id.toString(), {
      otp,
      expires: Date.now() + 5 * 60 * 1000
    });

    await sendOTPEmail(user.email, otp, user.username);

    res.json({
      success: true,
      message: 'New OTP sent to email'
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({
      message: 'Server error'
    });
  }
});

/* ======================================================
   CURRENT USER
   ====================================================== */
/* ======================================================
   AUTHENTICATOR APP MFA (TOTP)
   ====================================================== */
router.post('/mfa/setup', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const secret = speakeasy.generateSecret({
      name: `Secure Contact Form (${user.email})`,
      length: 32
    });

    // Store the secret (only enabled after verification)
    user.mfaSecret = secret.base32;
    user.mfaEnabled = false;
    await user.save();

    const qrCode = await generateQRCode(secret.otpauth_url);

    return res.json({
      success: true,
      message: 'MFA setup started. Scan the QR code in your authenticator app.',
      secret: secret.base32,
      qrCode
    });
  } catch (error) {
    console.error('MFA setup error:', error);
    return res.status(500).json({ message: 'Failed to setup MFA' });
  }
});

router.post('/mfa/enable', protect, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ message: 'token is required' });
    }

    const user = await User.findById(req.user._id);
    if (!user || !user.mfaSecret) {
      return res.status(400).json({ message: 'MFA not set up' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: String(token),
      window: 2
    });

    if (!verified) {
      return res.status(401).json({ message: 'Invalid verification code' });
    }

    user.mfaEnabled = true;
    await user.save();

    return res.json({
      success: true,
      message: 'Authenticator MFA enabled successfully'
    });
  } catch (error) {
    console.error('MFA enable error:', error);
    return res.status(500).json({ message: 'Failed to enable MFA' });
  }
});

router.post('/mfa/disable', protect, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ message: 'password is required' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isValid = await verifyPassword(password, user.passwordSalt, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    user.mfaEnabled = false;
    user.mfaSecret = null;
    await user.save();

    return res.json({
      success: true,
      message: 'Authenticator MFA disabled successfully'
    });
  } catch (error) {
    console.error('MFA disable error:', error);
    return res.status(500).json({ message: 'Failed to disable MFA' });
  }
});

/* ======================================================
   CURRENT USER
   ====================================================== */
router.get('/me', protect, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

/* ======================================================
   LOGOUT
   ====================================================== */
router.post('/logout', protect, (req, res) => {
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

export default router;
