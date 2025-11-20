# 🔐 Bedusec Admin Security Guide

## Default Admin Credentials

**Super Admin:**
- Username: `admin`
- Password: `Bedusec2024!`

**Creator Account:**
- Username: `creator` 
- Password: `CyberSecure123!`

## Security Features Implemented:

✅ **Secure Authentication System**
✅ **Session Management** (2-hour expiry)
✅ **Brute Force Protection** (5 attempts then 15-minute lock)
✅ **Role-Based Access Control**
✅ **Activity Logging**
✅ **Secure Logout**
✅ **Session Timeout Warnings**

## Important Security Notes:

1. **CHANGE DEFAULT PASSWORDS** immediately after setup
2. The admin panel is now at: `https://bedusec.netlify.app/login.html`
3. All access attempts are logged
4. Sessions automatically expire after 2 hours
5. Accounts lock after 5 failed attempts

## To Change Passwords:

Edit the `auth.js` file and update the `validUsers` object with new hashed passwords.

## Security Best Practices:

- Use strong, unique passwords
- Don't share admin credentials
- Log out after each session
- Monitor the activity logs regularly
- Keep your site updated

**Remember:** This is a client-side authentication system. For production use with sensitive data, implement a proper backend authentication system.
