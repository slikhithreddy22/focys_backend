import nodemailer from 'nodemailer';

const createTransporter = () => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    throw new Error('EMAIL_USER or EMAIL_PASS not loaded from .env');
  }

  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT),
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
};

export const sendOTPEmail = async (email, otp, username) => {
  const transporter = createTransporter();

  await transporter.sendMail({
    from: `"Secure Contact Form" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Your MFA Verification Code',
    html: `
      <h2>Multi-Factor Authentication</h2>
      <p>Hello ${username},</p>
      <p>Your OTP is:</p>
      <h1>${otp}</h1>
      <p>This OTP is valid for 5 minutes.</p>
    `
  });

  console.log('✅ OTP email sent successfully');
};

// Same improvements for sendContactNotification...
export const sendContactNotification = async (recipientEmail, senderName, subject) => {
  try {
    const transporter = createTransporter();

    const mailOptions = {
      from: `"Secure Contact Form" <${process.env.EMAIL_USER}>`,
      to: recipientEmail,
      subject: 'New Contact Form Received',
      html: `...`, // your existing HTML
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Notification email sent successfully → Message ID:', info.messageId);
    return true;
  } catch (error) {
    console.error('Error sending notification email:', error.message);
    return false;
  }
};
