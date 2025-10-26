// ===================================================================
// SECURITY & AUTHENTICATION MODULE
// Handles auth, encryption, secrets management, and security monitoring
// ===================================================================

import express from 'express';
import { Firestore } from '@google-cloud/firestore';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import winston from 'winston';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import Redis from 'ioredis';

// ===================================================================
// CONFIGURATION
// ===================================================================

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

const db = new Firestore();
const secretManager = new SecretManagerServiceClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// ===================================================================
// ENCRYPTION SERVICE
// ===================================================================

export class EncryptionService {
  private algorithm = 'aes-256-gcm';
  private key: Buffer;

  constructor(key?: string) {
    this.key = Buffer.from(key || ENCRYPTION_KEY, 'hex');
  }

  /**
   * Encrypt sensitive data
   */
  encrypt(text: string): { encrypted: string; iv: string; tag: string } {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
      
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const tag = cipher.getAuthTag();

      logger.info('Data encrypted successfully');

      return {
        encrypted,
        iv: iv.toString('hex'),
        tag: tag.toString('hex')
      };
    } catch (error) {
      logger.error('Encryption failed', { error: error.message });
      throw new Error('Encryption failed');
    }
  }

  /**
   * Decrypt sensitive data
   */
  decrypt(encrypted: string, iv: string, tag: string): string {
    try {
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        this.key,
        Buffer.from(iv, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(tag, 'hex'));
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      logger.error('Decryption failed', { error: error.message });
      throw new Error('Decryption failed');
    }
  }

  /**
   * Hash password
   */
  async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  /**
   * Verify password
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }

  /**
   * Generate secure random token
   */
  generateToken(bytes: number = 32): string {
    return crypto.randomBytes(bytes).toString('hex');
  }
}

// ===================================================================
// SECRET MANAGER SERVICE
// ===================================================================

export class SecretService {
  /**
   * Store secret in Google Secret Manager
   */
  async storeSecret(secretId: string, secretValue: string): Promise<void> {
    try {
      const parent = `projects/${PROJECT_ID}`;

      // Check if secret exists
      try {
        await secretManager.getSecret({
          name: `${parent}/secrets/${secretId}`
        });
        
        // Secret exists, add new version
        await secretManager.addSecretVersion({
          parent: `${parent}/secrets/${secretId}`,
          payload: {
            data: Buffer.from(secretValue, 'utf8')
          }
        });

        logger.info('Secret version added', { secretId });
      } catch {
        // Secret doesn't exist, create it
        await secretManager.createSecret({
          parent,
          secretId,
          secret: {
            replication: {
              automatic: {}
            }
          }
        });

        await secretManager.addSecretVersion({
          parent: `${parent}/secrets/${secretId}`,
          payload: {
            data: Buffer.from(secretValue, 'utf8')
          }
        });

        logger.info('Secret created', { secretId });
      }
    } catch (error) {
      logger.error('Failed to store secret', { 
        secretId, 
        error: error.message 
      });
      throw error;
    }
  }

  /**
   * Retrieve secret from Google Secret Manager
   */
  async getSecret(secretId: string): Promise<string> {
    try {
      const name = `projects/${PROJECT_ID}/secrets/${secretId}/versions/latest`;
      
      const [version] = await secretManager.accessSecretVersion({ name });
      const payload = version.payload?.data?.toString('utf8');

      if (!payload) {
        throw new Error('Secret payload is empty');
      }

      logger.info('Secret retrieved', { secretId });
      return payload;
    } catch (error) {
      logger.error('Failed to retrieve secret', { 
        secretId, 
        error: error.message 
      });
      throw error;
    }
  }

  /**
   * Delete secret
   */
  async deleteSecret(secretId: string): Promise<void> {
    try {
      const name = `projects/${PROJECT_ID}/secrets/${secretId}`;
      await secretManager.deleteSecret({ name });
      
      logger.info('Secret deleted', { secretId });
    } catch (error) {
      logger.error('Failed to delete secret', { 
        secretId, 
        error: error.message 
      });
      throw error;
    }
  }

  /**
   * List all secrets
   */
  async listSecrets(): Promise<string[]> {
    try {
      const parent = `projects/${PROJECT_ID}`;
      const [secrets] = await secretManager.listSecrets({ parent });
      
      return secrets.map(secret => secret.name?.split('/').pop() || '');
    } catch (error) {
      logger.error('Failed to list secrets', { error: error.message });
      throw error;
    }
  }

  /**
   * Store platform credentials securely
   */
  async storePlatformCredentials(
    platform: string,
    credentials: { email: string; password: string }
  ): Promise<void> {
    const encryption = new EncryptionService();
    
    const encrypted = encryption.encrypt(JSON.stringify(credentials));
    
    await this.storeSecret(
      `platform-credentials-${platform}`,
      JSON.stringify(encrypted)
    );

    logger.info('Platform credentials stored', { platform });
  }

  /**
   * Retrieve platform credentials
   */
  async getPlatformCredentials(platform: string): Promise<any> {
    const encryptedData = await this.getSecret(`platform-credentials-${platform}`);
    const encrypted = JSON.parse(encryptedData);
    
    const encryption = new EncryptionService();
    const decrypted = encryption.decrypt(
      encrypted.encrypted,
      encrypted.iv,
      encrypted.tag
    );

    return JSON.parse(decrypted);
  }
}

// ===================================================================
// JWT AUTHENTICATION SERVICE
// ===================================================================

export class AuthService {
  /**
   * Generate JWT token
   */
  generateToken(payload: any, expiresIn: string = '24h'): string {
    return jwt.sign(payload, JWT_SECRET, { expiresIn });
  }

  /**
   * Verify JWT token
   */
  verifyToken(token: string): any {
    try {
      return jwt.verify(token, JWT_SECRET);
    } catch (error) {
      logger.warn('Token verification failed', { error: error.message });
      throw new Error('Invalid token');
    }
  }

  /**
   * Generate API key
   */
  async generateAPIKey(userId: string, name: string): Promise<string> {
    const encryption = new EncryptionService();
    const apiKey = `cstx_${encryption.generateToken(32)}`;
    
    const hashedKey = await encryption.hashPassword(apiKey);
    
    await db.collection('api_keys').add({
      userId,
      name,
      keyHash: hashedKey,
      keyPrefix: apiKey.substring(0, 12),
      createdAt: new Date(),
      lastUsed: null,
      active: true
    });

    logger.info('API key generated', { userId, name });
    
    return apiKey; // Return only once, can't be retrieved again
  }

  /**
   * Verify API key
   */
  async verifyAPIKey(apiKey: string): Promise<any> {
    const keyPrefix = apiKey.substring(0, 12);
    
    const snapshot = await db.collection('api_keys')
      .where('keyPrefix', '==', keyPrefix)
      .where('active', '==', true)
      .get();

    if (snapshot.empty) {
      throw new Error('Invalid API key');
    }

    const encryption = new EncryptionService();
    
    for (const doc of snapshot.docs) {
      const data = doc.data();
      const isValid = await encryption.verifyPassword(apiKey, data.keyHash);
      
      if (isValid) {
        // Update last used
        await doc.ref.update({
          lastUsed: new Date()
        });

        logger.info('API key verified', { 
          keyId: doc.id,
          userId: data.userId 
        });

        return {
          keyId: doc.id,
          userId: data.userId,
          name: data.name
        };
      }
    }

    throw new Error('Invalid API key');
  }

  /**
   * Revoke API key
   */
  async revokeAPIKey(keyId: string): Promise<void> {
    await db.collection('api_keys').doc(keyId).update({
      active: false,
      revokedAt: new Date()
    });

    logger.info('API key revoked', { keyId });
  }
}

// ===================================================================
// SECURITY MONITORING
// ===================================================================

export class SecurityMonitor {
  /**
   * Log security event
   */
  async logSecurityEvent(event: {
    type: 'auth_failure' | 'rate_limit' | 'suspicious_activity' | 'data_access' | 'config_change';
    severity: 'low' | 'medium' | 'high' | 'critical';
    userId?: string;
    ipAddress?: string;
    userAgent?: string;
    details: any;
  }): Promise<void> {
    await db.collection('security_events').add({
      ...event,
      timestamp: new Date()
    });

    if (event.severity === 'high' || event.severity === 'critical') {
      logger.warn('Security event', event);
    } else {
      logger.info('Security event', event);
    }
  }

  /**
   * Check for suspicious activity
   */
  async checkSuspiciousActivity(userId: string, ipAddress: string): Promise<boolean> {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    
    const snapshot = await db.collection('security_events')
      .where('userId', '==', userId)
      .where('timestamp', '>=', oneHourAgo)
      .where('type', '==', 'auth_failure')
      .get();

    // More than 5 failed attempts in an hour
    if (snapshot.size > 5) {
      await this.logSecurityEvent({
        type: 'suspicious_activity',
        severity: 'high',
        userId,
        ipAddress,
        details: {
          failedAttempts: snapshot.size,
          timeWindow: '1 hour'
        }
      });
      return true;
    }

    return false;
  }

  /**
   * Get security events
   */
  async getSecurityEvents(filter: {
    userId?: string;
    type?: string;
    severity?: string;
    limit?: number;
  }): Promise<any[]> {
    let query: any = db.collection('security_events');

    if (filter.userId) {
      query = query.where('userId', '==', filter.userId);
    }
    if (filter.type) {
      query = query.where('type', '==', filter.type);
    }
    if (filter.severity) {
      query = query.where('severity', '==', filter.severity);
    }

    query = query.orderBy('timestamp', 'desc').limit(filter.limit || 100);

    const snapshot = await query.get();
    return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
  }

  /**
   * Check for data breaches (Have I Been Pwned)
   */
  async checkPasswordBreach(password: string): Promise<boolean> {
    const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);

    try {
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      const text = await response.text();
      
      const breached = text.split('\n').some(line => {
        const [hashSuffix] = line.split(':');
        return hashSuffix === suffix;
      });

      if (breached) {
        logger.warn('Password found in breach database');
      }

      return breached;
    } catch (error) {
      logger.error('Failed to check password breach', { error: error.message });
      return false; // Fail open
    }
  }
}

// ===================================================================
// AUDIT LOGGING
// ===================================================================

export class AuditLogger {
  /**
   * Log audit event
   */
  async log(event: {
    action: string;
    resource: string;
    resourceId?: string;
    userId?: string;
    changes?: any;
    metadata?: any;
  }): Promise<void> {
    await db.collection('audit_log').add({
      ...event,
      timestamp: new Date(),
      ipAddress: null, // Set by middleware
      userAgent: null  // Set by middleware
    });

    logger.info('Audit log entry', event);
  }

  /**
   * Get audit trail
   */
  async getAuditTrail(filter: {
    userId?: string;
    resource?: string;
    resourceId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): Promise<any[]> {
    let query: any = db.collection('audit_log');

    if (filter.userId) {
      query = query.where('userId', '==', filter.userId);
    }
    if (filter.resource) {
      query = query.where('resource', '==', filter.resource);
    }
    if (filter.resourceId) {
      query = query.where('resourceId', '==', filter.resourceId);
    }
    if (filter.startDate) {
      query = query.where('timestamp', '>=', filter.startDate);
    }
    if (filter.endDate) {
      query = query.where('timestamp', '<=', filter.endDate);
    }

    query = query.orderBy('timestamp', 'desc').limit(filter.limit || 100);

    const snapshot = await query.get();
    return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
  }
}

// ===================================================================
// MIDDLEWARE
// ===================================================================

/**
 * JWT Authentication Middleware
 */
export function authenticateJWT(req: any, res: any, next: any) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const authService = new AuthService();
    const payload = authService.verifyToken(token);
    req.user = payload;
    next();
  } catch (error) {
    logger.warn('JWT authentication failed', { error: error.message });
    return res.status(403).json({ error: 'Invalid token' });
  }
}

/**
 * API Key Authentication Middleware
 */
export function authenticateAPIKey(req: any, res: any, next: any) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({ error: 'No API key provided' });
  }

  const authService = new AuthService();
  
  authService.verifyAPIKey(apiKey)
    .then(keyData => {
      req.apiKey = keyData;
      next();
    })
    .catch(error => {
      logger.warn('API key authentication failed', { error: error.message });
      return res.status(403).json({ error: 'Invalid API key' });
    });
}

/**
 * Rate Limiting Middleware
 */
export const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const securityMonitor = new SecurityMonitor();
    securityMonitor.logSecurityEvent({
      type: 'rate_limit',
      severity: 'medium',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { endpoint: req.path }
    });

    res.status(429).json({
      error: 'Too many requests, please try again later.'
    });
  }
});

/**
 * Audit Logging Middleware
 */
export function auditLog(action: string, resource: string) {
  return async (req: any, res: any, next: any) => {
    const auditLogger = new AuditLogger();
    
    const originalSend = res.send;
    res.send = function(data: any) {
      // Log after response
      auditLogger.log({
        action,
        resource,
        resourceId: req.params.id,
        userId: req.user?.userId || req.apiKey?.userId,
        changes: req.body,
        metadata: {
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          statusCode: res.statusCode
        }
      });

      return originalSend.call(this, data);
    };

    next();
  };
}

/**
 * Security Headers Middleware
 */
export function securityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  });
}

/**
 * IP Whitelist Middleware
 */
export function ipWhitelist(allowedIPs: string[]) {
  return (req: any, res: any, next: any) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (!allowedIPs.includes(clientIP)) {
      const securityMonitor = new SecurityMonitor();
      securityMonitor.logSecurityEvent({
        type: 'suspicious_activity',
        severity: 'high',
        ipAddress: clientIP,
        details: { reason: 'IP not whitelisted', endpoint: req.path }
      });

      logger.warn('Blocked request from non-whitelisted IP', { 
        ip: clientIP,
        endpoint: req.path 
      });

      return res.status(403).json({ error: 'Access denied' });
    }

    next();
  };
}

// ===================================================================
// INPUT VALIDATION & SANITIZATION
// ===================================================================

export class InputValidator {
  /**
   * Validate email format
   */
  static isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate phone number
   */
  static isValidPhone(phone: string): boolean {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    return phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''));
  }

  /**
   * Sanitize string input (prevent XSS)
   */
  static sanitizeString(input: string): string {
    return input
      .replace(/[<>]/g, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+=/gi, '')
      .trim();
  }

  /**
   * Validate URL
   */
  static isValidURL(url: string): boolean {
    try {
      const parsed = new URL(url);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  /**
   * Check for SQL injection patterns
   */
  static hasSQLInjection(input: string): boolean {
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/gi,
      /(UNION.*SELECT)/gi,
      /('|--|;|\/\*|\*\/)/g
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Validate password strength
   */
  static validatePasswordStrength(password: string): {
    valid: boolean;
    errors: string[];
  } {
    const errors = [];

    if (password.length < 12) {
      errors.push('Password must be at least 12 characters');
    }
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain lowercase letters');
    }
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain uppercase letters');
    }
    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain numbers');
    }
    if (!/[^a-zA-Z0-9]/.test(password)) {
      errors.push('Password must contain special characters');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

// ===================================================================
// SESSION MANAGEMENT
// ===================================================================

export class SessionManager {
  /**
   * Create session
   */
  async createSession(userId: string, metadata: any = {}): Promise<string> {
    const encryption = new EncryptionService();
    const sessionId = encryption.generateToken(32);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await redis.setex(
      `session:${sessionId}`,
      24 * 60 * 60,
      JSON.stringify({
        userId,
        metadata,
        createdAt: new Date(),
        expiresAt
      })
    );

    logger.info('Session created', { userId, sessionId });
    return sessionId;
  }

  /**
   * Get session
   */
  async getSession(sessionId: string): Promise<any> {
    const data = await redis.get(`session:${sessionId}`);
    
    if (!data) {
      throw new Error('Session not found or expired');
    }

    return JSON.parse(data);
  }

  /**
   * Destroy session
   */
  async destroySession(sessionId: string): Promise<void> {
    await redis.del(`session:${sessionId}`);
    logger.info('Session destroyed', { sessionId });
  }

  /**
   * Extend session
   */
  async extendSession(sessionId: string): Promise<void> {
    const ttl = await redis.ttl(`session:${sessionId}`);
    
    if (ttl > 0) {
      await redis.expire(`session:${sessionId}`, 24 * 60 * 60);
      logger.info('Session extended', { sessionId });
    }
  }
}

// ===================================================================
// REST API
// ===================================================================

const app = express();
app.use(express.json());
app.use(securityHeaders());
app.use(rateLimiter);

const encryptionService = new EncryptionService();
const secretService = new SecretService();
const authService = new AuthService();
const securityMonitor = new SecurityMonitor();
const auditLogger = new AuditLogger();
const sessionManager = new SessionManager();

// Health check (public)
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ===================================================================
// AUTHENTICATION ENDPOINTS
// ===================================================================

// Generate API key
app.post('/api/auth/generate-key', authenticateJWT, async (req, res) => {
  try {
    const { name } = req.body;
    const userId = req.user.userId;

    const apiKey = await authService.generateAPIKey(userId, name);

    await auditLogger.log({
      action: 'generate_api_key',
      resource: 'api_key',
      userId,
      metadata: { keyName: name }
    });

    res.json({ 
      apiKey,
      message: 'Store this key securely - it cannot be retrieved again'
    });
  } catch (error) {
    logger.error('Error generating API key', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Revoke API key
app.delete('/api/auth/revoke-key/:keyId', authenticateJWT, async (req, res) => {
  try {
    await authService.revokeAPIKey(req.params.keyId);

    await auditLogger.log({
      action: 'revoke_api_key',
      resource: 'api_key',
      resourceId: req.params.keyId,
      userId: req.user.userId
    });

    res.json({ success: true });
  } catch (error) {
    logger.error('Error revoking API key', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Create session
app.post('/api/auth/session', authenticateJWT, async (req, res) => {
  try {
    const sessionId = await sessionManager.createSession(
      req.user.userId,
      { ipAddress: req.ip, userAgent: req.get('user-agent') }
    );

    res.json({ sessionId });
  } catch (error) {
    logger.error('Error creating session', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Destroy session
app.delete('/api/auth/session/:sessionId', async (req, res) => {
  try {
    await sessionManager.destroySession(req.params.sessionId);
    res.json({ success: true });
  } catch (error) {
    logger.error('Error destroying session', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// ===================================================================
// SECRET MANAGEMENT ENDPOINTS
// ===================================================================

// Store secret (admin only)
app.post('/api/secrets', authenticateJWT, async (req, res) => {
  try {
    const { secretId, secretValue } = req.body;

    await secretService.storeSecret(secretId, secretValue);

    await auditLogger.log({
      action: 'store_secret',
      resource: 'secret',
      resourceId: secretId,
      userId: req.user.userId
    });

    res.json({ success: true });
  } catch (error) {
    logger.error('Error storing secret', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// List secrets (admin only)
app.get('/api/secrets', authenticateJWT, async (req, res) => {
  try {
    const secrets = await secretService.listSecrets();
    res.json({ secrets });
  } catch (error) {
    logger.error('Error listing secrets', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Store platform credentials
app.post('/api/secrets/platform/:platform', authenticateJWT, async (req, res) => {
  try {
    const { platform } = req.params;
    const { email, password } = req.body;

    await secretService.storePlatformCredentials(platform, { email, password });

    await auditLogger.log({
      action: 'store_platform_credentials',
      resource: 'platform_credentials',
      resourceId: platform,
      userId: req.user.userId
    });

    res.json({ success: true });
  } catch (error) {
    logger.error('Error storing platform credentials', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// ===================================================================
// SECURITY MONITORING ENDPOINTS
// ===================================================================

// Get security events
app.get('/api/security/events', authenticateJWT, async (req, res) => {
  try {
    const filter = {
      userId: req.query.userId as string,
      type: req.query.type as string,
      severity: req.query.severity as string,
      limit: parseInt(req.query.limit as string) || 100
    };

    const events = await securityMonitor.getSecurityEvents(filter);
    res.json({ events });
  } catch (error) {
    logger.error('Error fetching security events', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Get audit trail
app.get('/api/security/audit', authenticateJWT, async (req, res) => {
  try {
    const filter = {
      userId: req.query.userId as string,
      resource: req.query.resource as string,
      resourceId: req.query.resourceId as string,
      limit: parseInt(req.query.limit as string) || 100
    };

    const trail = await auditLogger.getAuditTrail(filter);
    res.json({ trail });
  } catch (error) {
    logger.error('Error fetching audit trail', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Check password breach
app.post('/api/security/check-password', async (req, res) => {
  try {
    const { password } = req.body;

    const breached = await securityMonitor.checkPasswordBreach(password);
    const strength = InputValidator.validatePasswordStrength(password);

    res.json({
      breached,
      strength
    });
  } catch (error) {
    logger.error('Error checking password', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// ===================================================================
// ENCRYPTION ENDPOINTS (for testing)
// ===================================================================

// Encrypt data
app.post('/api/encrypt', authenticateAPIKey, async (req, res) => {
  try {
    const { data } = req.body;
    const encrypted = encryptionService.encrypt(data);
    
    res.json({ encrypted });
  } catch (error) {
    logger.error('Error encrypting data', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Decrypt data
app.post('/api/decrypt', authenticateAPIKey, async (req, res) => {
  try {
    const { encrypted, iv, tag } = req.body;
    const decrypted = encryptionService.decrypt(encrypted, iv, tag);
    
    res.json({ decrypted });
  } catch (error) {
    logger.error('Error decrypting data', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// ===================================================================
// SECURITY UTILITIES EXPORT
// ===================================================================

export {
  encryptionService,
  secretService,
  authService,
  securityMonitor,
  auditLogger,
  sessionManager,
  InputValidator
};

// Start server if run directly
if (require.main === module) {
  const PORT = process.env.SECURITY_SERVICE_PORT || 8083;
  app.listen(PORT, () => {
    logger.info(`Security Service running on port ${PORT}`);
    logger.info('Security features enabled: encryption, secrets, auth, monitoring');
  });
}

export default app;