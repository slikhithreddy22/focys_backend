import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from '../models/User.js';
import { generateSalt, hashPassword } from '../utils/hashing.js';
import { generateKeyPair } from '../utils/encryption.js';

dotenv.config();

const createAdmin = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    // Admin credentials
    const adminData = {
      username: 'admin',
      email: 'admin@secure.com',
      password: 'Admin@123',
      role: 'admin'
    };

    // Check if admin exists
    const existingAdmin = await User.findOne({ username: adminData.username });
    if (existingAdmin) {
      console.log('❌ Admin user already exists!');
      process.exit(0);
    }

    // Generate salt and hash password
    const salt = generateSalt();
    const passwordHash = await hashPassword(adminData.password, salt);

    // Generate RSA key pair
    const { publicKey, privateKey } = generateKeyPair();

    // Create admin user
    const admin = await User.create({
      username: adminData.username,
      email: adminData.email,
      passwordHash,
      passwordSalt: salt,
      role: adminData.role,
      publicKey,
      isActive: true
    });

    console.log('✅ Admin user created successfully!');
    console.log('📧 Email:', adminData.email);
    console.log('👤 Username:', adminData.username);
    console.log('🔑 Password:', adminData.password);
    console.log('🔐 Private Key:', privateKey);
    console.log('\n⚠️  Please save the private key securely!');

    // Create manager
    const managerData = {
      username: 'manager',
      email: 'manager@secure.com',
      password: 'Manager@123',
      role: 'manager'
    };

    const managerSalt = generateSalt();
    const managerPasswordHash = await hashPassword(managerData.password, managerSalt);
    const managerKeys = generateKeyPair();

    await User.create({
      username: managerData.username,
      email: managerData.email,
      passwordHash: managerPasswordHash,
      passwordSalt: managerSalt,
      role: managerData.role,
      publicKey: managerKeys.publicKey,
      isActive: true
    });

    console.log('\n✅ Manager user created successfully!');
    console.log('📧 Email:', managerData.email);
    console.log('👤 Username:', managerData.username);
    console.log('🔑 Password:', managerData.password);

    // Create regular user
    const userData = {
      username: 'user',
      email: 'user@secure.com',
      password: 'User@123',
      role: 'user'
    };

    const userSalt = generateSalt();
    const userPasswordHash = await hashPassword(userData.password, userSalt);
    const userKeys = generateKeyPair();

    await User.create({
      username: userData.username,
      email: userData.email,
      passwordHash: userPasswordHash,
      passwordSalt: userSalt,
      role: userData.role,
      publicKey: userKeys.publicKey,
      isActive: true
    });

    console.log('\n✅ Regular user created successfully!');
    console.log('📧 Email:', userData.email);
    console.log('👤 Username:', userData.username);
    console.log('🔑 Password:', userData.password);

    console.log('\n✅ All test users created!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error creating users:', error);
    process.exit(1);
  }
};

createAdmin();