# Multi-Factor Authentication (MFA) Implementation Guide

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [MFA Types Supported](#mfa-types-supported)
- [Implementation](#implementation)
- [API Usage](#api-usage)
- [Security Considerations](#security-considerations)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

The library provides a comprehensive MFA implementation with support for multiple authentication methods:

- **TOTP** (Time-based One-Time Password) - Google Authenticator, Authy, etc.
- **Email** - Verification codes sent via email
- **SMS** - Verification codes sent via SMS
- **Backup Codes** - Recovery codes for account access

## 🏗️ Architecture

### Key Components

1. **SecurityService** - Core verification engine
   - Manages challenge verifiers using Strategy pattern
   - Provides `verifyChallenge()` for all verification types
   - Built-in verifiers: TOTP, SecureCode, BackupCode

2. **EnhancedUserService** - MFA management layer
   - User-facing MFA methods
   - Integrates with SecurityService
   - Manages challenge lifecycle

3. **Challenge Verifiers** - Pluggable verification strategies
   - `TOTPVerifier` - RFC 6238 compliant TOTP
   - `SecureCodeVerifier` - SHA-256 hashed codes
   - `BackupCodeVerifier` - Backup recovery codes

### Data Flow

```
User Input → EnhancedUserService → SecurityService → Verifier → Result
                    ↓                      ↓
            Challenge Management    Challenge Verification
```

## 🔐 MFA Types Supported

### 1. TOTP (Time-Based One-Time Password)

**Use Case**: Google Authenticator, Authy, Microsoft Authenticator

**Characteristics**:
- ✅ Stateless (no DB persistence)
- ✅ 30-second time window
- ✅ RFC 6238 compliant
- ✅ Works offline

**Implementation**:
```typescript
import { EnhancedUserService, MFAType } from 'open-bauth';

// Setup TOTP
const setupResult = await enhancedUserService.setupMFA(
  userId,
  MFAType.TOTP,
  {
    secret: 'JBSWY3DPEHPK3PXP', // Base32 encoded secret
    is_primary: true
  }
);

// Generate QR code for user to scan
const qrCodeUrl = `otpauth://totp/MyApp:${user.email}?secret=${secret}&issuer=MyApp`;

// Verify code from user's authenticator app
const verifyResult = await enhancedUserService.verifyMFA(
  userId,
  '123456' // 6-digit code from app
);
```

### 2. Email Verification Codes

**Use Case**: Email-based 2FA, email verification

**Characteristics**:
- ✅ Requires DB persistence
- ✅ 10-minute expiry
- ✅ SHA-256 hashed storage
- ✅ Audit trail maintained

**Implementation**:
```typescript
import { EnhancedUserService, MFAType } from 'open-bauth';

// Setup Email MFA
await enhancedUserService.setupMFA(
  userId,
  MFAType.EMAIL,
  {
    email: user.email,
    is_primary: false
  }
);

// Generate and send code
const challengeResult = await enhancedUserService.generateMFAChallenge(
  userId,
  MFAType.EMAIL
);

if (challengeResult.success) {
  // Send email with the code
  await emailService.send({
    to: user.email,
    subject: 'Your verification code',
    text: `Your code is: ${challengeResult.code}\n\nExpires in 10 minutes.`
  });
  
  // Store challengeId in session
  session.mfaChallengeId = challengeResult.challenge!.challenge_id;
}

// Later, when user enters the code
const verifyResult = await enhancedUserService.verifyMFACode(
  userId,
  userInputCode,
  session.mfaChallengeId
);

if (verifyResult.success) {
  // Code verified, challenge marked as is_solved: true
  console.log('✅ Email verification successful');
}
```

### 3. SMS Verification Codes

**Use Case**: SMS-based 2FA

**Characteristics**:
- Same as Email verification
- Requires SMS service integration

**Implementation**:
```typescript
// Setup SMS MFA
await enhancedUserService.setupMFA(
  userId,
  MFAType.SMS,
  {
    phone_number: '+1234567890',
    is_primary: false
  }
);

// Generate and send code
const challengeResult = await enhancedUserService.generateMFAChallenge(
  userId,
  MFAType.SMS
);

if (challengeResult.success) {
  // Send SMS
  await smsService.send({
    to: '+1234567890',
    message: `Your verification code is: ${challengeResult.code}`
  });
  
  session.mfaChallengeId = challengeResult.challenge!.challenge_id;
}

// Verify code
const verifyResult = await enhancedUserService.verifyMFACode(
  userId,
  userInputCode,
  session.mfaChallengeId
);
```

## 🔧 Implementation

### Complete Login Flow with MFA

```typescript
import { AuthService, EnhancedUserService, MFAType } from 'open-bauth';

async function loginWithMFA(email: string, password: string, mfaCode?: string) {
  // 1. Authenticate credentials
  const authResult = await authService.login({ email, password });
  
  if (!authResult.success) {
    return { error: 'Invalid credentials' };
  }
  
  const user = authResult.user!;
  
  // 2. Check if MFA is enabled
  const mfaConfigs = await enhancedUserService.getEnabledMFAConfigurations(user.id);
  
  if (mfaConfigs.length === 0) {
    // No MFA - return token directly
    return { success: true, token: authResult.token };
  }
  
  // 3. Get primary MFA method
  const primaryMFA = await enhancedUserService.getPrimaryMFAConfiguration(user.id);
  
  if (!primaryMFA) {
    return { error: 'MFA configuration error' };
  }
  
  // 4. If no MFA code provided, send it
  if (!mfaCode) {
    if (primaryMFA.mfa_type === MFAType.EMAIL || primaryMFA.mfa_type === MFAType.SMS) {
      // Generate and send code
      const challengeResult = await enhancedUserService.generateMFAChallenge(
        user.id,
        primaryMFA.mfa_type
      );
      
      if (challengeResult.success) {
        // Send code via email/sms
        await sendVerificationCode(primaryMFA, challengeResult.code!);
        
        return {
          mfaRequired: true,
          mfaType: primaryMFA.mfa_type,
          challengeId: challengeResult.challenge!.challenge_id,
          message: `Verification code sent to your ${primaryMFA.mfa_type}`
        };
      }
    } else {
      // TOTP - user must enter code from app
      return {
        mfaRequired: true,
        mfaType: MFAType.TOTP,
        message: 'Enter code from your authenticator app'
      };
    }
  }
  
  // 5. Verify MFA code
  let mfaResult;
  
  if (primaryMFA.mfa_type === MFAType.TOTP) {
    // Verify TOTP
    mfaResult = await enhancedUserService.verifyMFA(user.id, mfaCode);
  } else {
    // Verify Email/SMS code
    const challengeId = session.mfaChallengeId; // From previous response
    mfaResult = await enhancedUserService.verifyMFACode(
      user.id,
      mfaCode,
      challengeId
    );
  }
  
  if (!mfaResult.success) {
    return { error: 'Invalid MFA code' };
  }
  
  // 6. MFA verified - return token
  return { success: true, token: authResult.token };
}
```

### Setting Up MFA for Users

```typescript
async function setupMFAForUser(userId: string, mfaType: MFAType) {
  let config: any;
  
  switch (mfaType) {
    case MFAType.TOTP:
      // Generate TOTP secret
      const secret = generateTOTPSecret(); // Use crypto library
      
      config = {
        secret: secret,
        is_primary: true
      };
      
      // Setup MFA
      const setupResult = await enhancedUserService.setupMFA(
        userId,
        MFAType.TOTP,
        config
      );
      
      if (setupResult.success) {
        // Generate QR code for user
        const qrCodeUrl = generateQRCode(secret, user.email);
        return { success: true, qrCodeUrl, secret };
      }
      break;
      
    case MFAType.EMAIL:
      config = {
        email: user.email,
        is_primary: false
      };
      
      const emailSetup = await enhancedUserService.setupMFA(
        userId,
        MFAType.EMAIL,
        config
      );
      
      return emailSetup;
      
    case MFAType.SMS:
      config = {
        phone_number: user.phone_number,
        is_primary: false
      };
      
      return await enhancedUserService.setupMFA(
        userId,
        MFAType.SMS,
        config
      );
  }
}
```

## 🛡️ Security Considerations

### 1. Challenge Management

**❌ INCORRECT - Direct SQL Delete**:
```typescript
// DON'T DO THIS
db.run("DELETE FROM verification_tokens WHERE id = ?", [tokenId]);
```

**✅ CORRECT - Mark as Solved**:
```typescript
// DO THIS
await challengeController.update(challenge.id, {
  is_solved: true,
  solved_at: new Date().toISOString()
});
```

**Why?**:
- ✅ Maintains audit trail
- ✅ Prevents reuse automatically
- ✅ Enables security analysis
- ✅ Compliance friendly
- ✅ Better debugging

### 2. Code Storage

**Always hash verification codes**:
```typescript
import { createHash } from 'crypto';

// Generate code
const code = Math.floor(100000 + Math.random() * 900000).toString();

// Hash for storage
const salt = securityService.generateSecureToken(16);
const codeHash = createHash('sha256')
  .update(code + salt)
  .digest('hex');

// Store only the hash
await challengeController.create({
  challenge_data: JSON.stringify({
    expectedHash: codeHash,
    salt: salt
  })
});

// Send plain code to user (ONLY HERE)
await sendEmail(user.email, `Code: ${code}`);
```

### 3. Challenge Cleanup

**Setup periodic cleanup**:
```typescript
import cron from 'node-cron';

// Run daily at 3 AM
cron.schedule('0 3 * * *', async () => {
  try {
    const count = await enhancedUserService.cleanupExpiredChallenges(7);
    logger.info(`Cleaned up ${count} old challenges`);
  } catch (error) {
    logger.error('Challenge cleanup failed:', error);
  }
});
```

### 4. Rate Limiting

**Implement rate limiting for MFA endpoints**:
```typescript
import rateLimit from 'express-rate-limit';

const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many MFA attempts, please try again later'
});

app.post('/api/mfa/verify', mfaLimiter, async (req, res) => {
  // Handle MFA verification
});
```

## 🎯 Best Practices

### 1. Choose the Right MFA Type

| Scenario | Recommended MFA | Why |
|----------|----------------|-----|
| High Security Apps | TOTP | Offline, no SMS/Email dependency |
| User Convenience | Email | Easy to implement, familiar |
| Mobile Apps | TOTP + Backup Codes | Best UX for mobile users |
| Enterprise | TOTP + Device Verification | Most secure, works offline |

### 2. Multiple MFA Methods

**Set up fallback methods**:
```typescript
// Primary: TOTP
await enhancedUserService.setupMFA(userId, MFAType.TOTP, {
  secret: totpSecret,
  is_primary: true
});

// Fallback: Email
await enhancedUserService.setupMFA(userId, MFAType.EMAIL, {
  email: user.email,
  is_primary: false
});

// Recovery: Backup codes
await enhancedUserService.setupMFA(userId, MFAType.BACKUP_CODE, {
  backup_codes: generateBackupCodes(10) // Generate 10 codes
});
```

### 3. User Experience

**Progressive MFA**:
- Start with Email MFA (easy onboarding)
- Encourage TOTP upgrade later
- Always provide backup mechanisms

**Clear Communication**:
```typescript
if (mfaResult.mfaType === MFAType.TOTP) {
  return res.json({
    message: 'Enter the 6-digit code from your authenticator app',
    helpUrl: '/help/totp-setup'
  });
} else if (mfaResult.mfaType === MFAType.EMAIL) {
  return res.json({
    message: 'A verification code has been sent to your email',
    expiresIn: '10 minutes'
  });
}
```

### 4. Testing

**Example test for TOTP**:
```typescript
import { TOTPVerifier } from 'open-bauth';

describe('MFA TOTP', () => {
  it('should verify valid TOTP code', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    
    // Setup MFA
    await enhancedUserService.setupMFA(userId, MFAType.TOTP, { secret });
    
    // Generate valid code
    const totpVerifier = new TOTPVerifier();
    const validCode = totpVerifier.generateTOTP(secret);
    
    // Verify
    const result = await enhancedUserService.verifyMFA(userId, validCode);
    
    expect(result.success).toBe(true);
  });
  
  it('should reject expired email code', async () => {
    const challengeResult = await enhancedUserService.generateMFAChallenge(
      userId,
      MFAType.EMAIL
    );
    
    // Mark challenge as expired
    await challengeController.update(challengeResult.challenge!.id, {
      expires_at: new Date(Date.now() - 1000).toISOString() // 1 second ago
    });
    
    const result = await enhancedUserService.verifyMFACode(
      userId,
      challengeResult.code!,
      challengeResult.challenge!.challenge_id
    );
    
    expect(result.success).toBe(false);
    expect(result.error.message).toContain('expired');
  });
});
```

## 🐛 Troubleshooting

### Common Issues

#### 1. "MFA not configured" error

**Cause**: User doesn't have MFA setup
**Solution**: Check if MFA is setup before requiring it

```typescript
const mfaConfigs = await enhancedUserService.getEnabledMFAConfigurations(userId);

if (mfaConfigs.length === 0) {
  // Redirect to MFA setup page
  return { setupRequired: true };
}
```

#### 2. TOTP codes not working

**Cause**: Clock skew between server and client
**Solution**: TOTPVerifier has built-in 30s window

```typescript
// Check server time
console.log('Server time:', new Date().toISOString());

// Verify secret is correct
const secret = mfaConfig.secret;
console.log('Secret:', secret);

// Generate valid code manually
const totpVerifier = new TOTPVerifier();
const validCode = totpVerifier.generateTOTP(secret);
console.log('Valid code at this moment:', validCode);
```

#### 3. Email codes not arriving

**Cause**: Challenge creation failing or email service issue
**Solution**: Check both

```typescript
const result = await enhancedUserService.generateMFAChallenge(userId, MFAType.EMAIL);

if (!result.success) {
  console.error('Challenge creation failed:', result.error);
  return;
}

console.log('Challenge created:', result.challenge!.challenge_id);
console.log('Code to send:', result.code);

// Check email service
try {
  await emailService.send({...});
  console.log('Email sent successfully');
} catch (error) {
  console.error('Email sending failed:', error);
}
```

#### 4. Challenges not being marked as solved

**Cause**: Not calling `update()` after verification
**Solution**: Always update challenge status

```typescript
const result = await enhancedUserService.verifyMFACode(userId, code, challengeId);

if (result.success) {
  // Challenge is automatically marked as solved inside verifyMFACode
  
  // Verify it's marked
  const challenge = await challengeController.findFirst({ challenge_id: challengeId });
  console.log('Challenge solved:', challenge.data?.is_solved); // Should be true
}
```

---

## 📚 Additional Resources

- [TOTP RFC 6238](https://tools.ietf.org/html/rfc6238)
- [SecurityService Documentation](./services.md#securityservice)
- [EnhancedUserService Documentation](./services.md#enhanceduserservice)
- [Example Implementation](./.gemini/mfa_usage_examples.ts)
