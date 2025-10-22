'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const users = [];

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

const isNotAuthenticated = (req, res, next) => {
  const token = req.headers['authorization'];

  if (token) {
    return res.status(400).json({ error: 'Already authenticated' });
  }
  next();
};

// Password validation
const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*]/.test(password);

  return (
    password.length >= minLength &&
    hasUpperCase &&
    hasLowerCase &&
    hasNumbers &&
    hasSpecialChar
  );
};

// Registration
app.post('/register', isNotAuthenticated, async (req, res) => {
  const { name, email, password } = req.body;
  const PASSWORD_ERROR =
    'Password must be at least 8 characters and contain uppercase, lowercase, numbers and special characters'; // eslint-disable-line max-len

  if (!validatePassword(password)) {
    return res.status(400).json({
      error: PASSWORD_ERROR,
    });
  }

  const userExists = users.find((u) => u.email === email);

  if (userExists) {
    return res.status(400).json({ error: 'Email already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const activationToken = uuidv4();

  const newUser = {
    name,
    email,
    password: hashedPassword,
    active: false,
    activationToken,
  };

  users.push(newUser);

  // Send activation email
  const activationLink = `${process.env.BASE_URL}/activate/${activationToken}`;

  await transporter.sendMail({
    to: email,
    subject: 'Activate your account',
    html: `Click <a href="${activationLink}">here</a> to activate your account`,
  });

  res.status(201).json({
    message:
      'Registration successful. Please check your email to activate account.',
  });
});

// Activation
app.get('/activate/:token', isNotAuthenticated, (req, res) => {
  const { token } = req.params;
  const user = users.find((u) => u.activationToken === token);

  if (!user) {
    return res.status(400).json({ error: 'Invalid activation token' });
  }

  user.active = true;
  user.activationToken = null;

  res.redirect('/profile');
});

// Login
app.post('/login', isNotAuthenticated, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!user.active) {
    return res
      .status(403)
      .json({ error: 'Please activate your account first' });
  }

  const token = jwt.sign({ id: user.email }, process.env.JWT_SECRET);

  res.json({ token });
});

// Logout
app.post('/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// Password reset request
app.post('/reset-password', isNotAuthenticated, async (req, res) => {
  const { email } = req.body;
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const resetToken = uuidv4();

  user.resetToken = resetToken;
  user.resetTokenExpiry = Date.now() + 3600000; // 1 hour

  const resetLink = `${process.env.BASE_URL}/reset-password/${resetToken}`;

  await transporter.sendMail({
    to: email,
    subject: 'Reset your password',
    html: `Click <a href="${resetLink}">here</a> to reset your password`,
  });

  res.json({ message: 'Password reset email sent' });
});

// Password reset confirmation
app.post('/reset-password/:token', isNotAuthenticated, async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  const user = users.find(
    (u) => u.resetToken === token && u.resetTokenExpiry > Date.now(),
  );

  if (!user) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Invalid password format' });
  }

  user.password = await bcrypt.hash(password, 10);
  user.resetToken = null;
  user.resetTokenExpiry = null;

  res.json({ message: 'Password reset successful' });
});

// Profile
app.get('/profile', authenticateToken, (req, res) => {
  const user = users.find((u) => u.email === req.user.id);

  res.json({ name: user.name, email: user.email });
});

// Update profile
app.put('/profile', authenticateToken, async (req, res) => {
  const user = users.find((u) => u.email === req.user.id);
  const { name, currentPassword, newPassword, newEmail } = req.body;

  if (name) {
    user.name = name;
  }

  if (newPassword) {
    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({ error: 'Invalid password format' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
  }

  if (newEmail) {
    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const emailExists = users.find((u) => u.email === newEmail);

    if (emailExists) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    const oldEmail = user.email;

    user.email = newEmail;

    // Notify old email
    await transporter.sendMail({
      to: oldEmail,
      subject: 'Email Changed',
      text: `Your email has been changed to ${newEmail}`,
    });
  }

  res.json({ message: 'Profile updated successfully' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Page not found' });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`); // eslint-disable-line no-console
});
