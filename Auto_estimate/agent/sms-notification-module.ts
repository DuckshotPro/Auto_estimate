// ===================================================================
// SMS NOTIFICATION & ALERT MODULE
// Handles SMS notifications via Twilio with smart throttling
// ===================================================================

import express from 'express';
import { Firestore } from '@google-cloud/firestore';
import winston from 'winston';
import twilio from 'twilio';
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
    new winston.transports.File({ filename: 'sms-notifications.log' })
  ]
});

const db = new Firestore();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// ===================================================================
// NOTIFICATION TYPES & PRIORITIES
// ===================================================================

enum NotificationPriority {
  LOW = 'low',           // Batch into daily digest
  MEDIUM = 'medium',     // Send within 1 hour
  HIGH = 'high',         // Send within 15 minutes
  URGENT = 'urgent'      // Send immediately
}

enum NotificationType {
  // Estimate-related
  ESTIMATE_NEEDS_REVIEW = 'estimate_needs_review',
  ESTIMATE_AUTO_SENT = 'estimate_auto_sent',
  ESTIMATE_ERROR = 'estimate_error',
  
  // Budget/Cost alerts
  COST_THRESHOLD = 'cost_threshold',
  RATE_LIMIT_WARNING = 'rate_limit_warning',
  DAILY_BUDGET_EXCEEDED = 'daily_budget_exceeded',
  
  // System alerts
  SYSTEM_ERROR = 'system_error',
  AUTHENTICATION_FAILURE = 'authentication_failure',
  SERVICE_DEGRADED = 'service_degraded',
  
  // Daily summaries
  DAILY_DIGEST = 'daily_digest',
  WEEKLY_SUMMARY = 'weekly_summary'
}

interface NotificationConfig {
  type: NotificationType;
  priority: NotificationPriority;
  throttleMinutes?: number;  // Minimum time between same notifications
  batchable?: boolean;       // Can be included in digest
  template: (data: any) => string;
}

// ===================================================================
// NOTIFICATION TEMPLATES
// ===================================================================

const NOTIFICATION_TEMPLATES: Record<NotificationType, NotificationConfig> = {
  [NotificationType.ESTIMATE_NEEDS_REVIEW]: {
    type: NotificationType.ESTIMATE_NEEDS_REVIEW,
    priority: NotificationPriority.HIGH,
    throttleMinutes: 30,
    batchable: true,
    template: (data) => 
      `🔍 Estimate needs review\n` +
      `From: ${data.clientEmail}\n` +
      `Confidence: ${(data.confidence * 100).toFixed(0)}%\n` +
      `Issues: ${data.issues.join(', ')}\n` +
      `Review: ${data.reviewUrl}`
  },

  [NotificationType.ESTIMATE_AUTO_SENT]: {
    type: NotificationType.ESTIMATE_AUTO_SENT,
    priority: NotificationPriority.LOW,
    batchable: true,
    template: (data) => 
      `✅ Estimate auto-sent\n` +
      `To: ${data.clientEmail}\n` +
      `Amount: $${data.amount.toFixed(2)}\n` +
      `Ref: ${data.reference}`
  },

  [NotificationType.ESTIMATE_ERROR]: {
    type: NotificationType.ESTIMATE_ERROR,
    priority: NotificationPriority.URGENT,
    throttleMinutes: 15,
    template: (data) => 
      `❌ Estimate processing failed\n` +
      `Email: ${data.emailId}\n` +
      `Error: ${data.error}\n` +
      `Manual intervention needed`
  },

  [NotificationType.COST_THRESHOLD]: {
    type: NotificationType.COST_THRESHOLD,
    priority: NotificationPriority.MEDIUM,
    throttleMinutes: 60,
    template: (data) => 
      `💰 Cost alert: ${data.percentage}% of daily budget\n` +
      `Current: $${data.current.toFixed(2)}\n` +
      `Limit: $${data.limit.toFixed(2)}\n` +
      `Time: ${new Date().toLocaleTimeString()}`
  },

  [NotificationType.RATE_LIMIT_WARNING]: {
    type: NotificationType.RATE_LIMIT_WARNING,
    priority: NotificationPriority.HIGH,
    throttleMinutes: 30,
    template: (data) => 
      `⚠️ Rate limit warning\n` +
      `Provider: ${data.provider}\n` +
      `${data.warnings.join('\n')}`
  },

  [NotificationType.DAILY_BUDGET_EXCEEDED]: {
    type: NotificationType.DAILY_BUDGET_EXCEEDED,
    priority: NotificationPriority.URGENT,
    template: (data) => 
      `🚨 DAILY BUDGET EXCEEDED\n` +
      `Spent: $${data.spent.toFixed(2)}\n` +
      `Budget: $${data.budget.toFixed(2)}\n` +
      `Processing paused until tomorrow`
  },

  [NotificationType.SYSTEM_ERROR]: {
    type: NotificationType.SYSTEM_ERROR,
    priority: NotificationPriority.URGENT,
    throttleMinutes: 15,
    template: (data) => 
      `🚨 System error\n` +
      `Service: ${data.service}\n` +
      `Error: ${data.error}\n` +
      `Time: ${new Date().toLocaleTimeString()}`
  },

  [NotificationType.AUTHENTICATION_FAILURE]: {
    type: NotificationType.AUTHENTICATION_FAILURE,
    priority: NotificationPriority.URGENT,
    template: (data) => 
      `🔐 Auth failure: ${data.platform}\n` +
      `Action: Update credentials\n` +
      `Dashboard: ${data.dashboardUrl}`
  },

  [NotificationType.SERVICE_DEGRADED]: {
    type: NotificationType.SERVICE_DEGRADED,
    priority: NotificationPriority.HIGH,
    throttleMinutes: 60,
    template: (data) => 
      `⚠️ Service degraded\n` +
      `${data.service}: ${data.status}\n` +
      `Impact: ${data.impact}`
  },

  [NotificationType.DAILY_DIGEST]: {
    type: NotificationType.DAILY_DIGEST,
    priority: NotificationPriority.LOW,
    template: (data) => 
      `📊 Daily Summary\n` +
      `Estimates processed: ${data.processed}\n` +
      `Auto-sent: ${data.autoSent}\n` +
      `Need review: ${data.needReview}\n` +
      `Errors: ${data.errors}\n` +
      `Cost: $${data.cost.toFixed(2)}\n` +
      `Dashboard: ${data.dashboardUrl}`
  },

  [NotificationType.WEEKLY_SUMMARY]: {
    type: NotificationType.WEEKLY_SUMMARY,
    priority: NotificationPriority.LOW,
    template: (data) => 
      `📈 Weekly Summary\n` +
      `Total estimates: ${data.total}\n` +
      `Avg/day: ${data.avgPerDay}\n` +
      `Auto-sent rate: ${data.autoSentRate}%\n` +
      `Total revenue potential: $${data.revenue.toFixed(2)}\n` +
      `API cost: $${data.apiCost.toFixed(2)}`
  }
};

// ===================================================================
// NOTIFICATION SERVICE
// ===================================================================

export class NotificationService {
  private phoneNumber: string;

  constructor(phoneNumber?: string) {
    this.phoneNumber = phoneNumber || process.env.NOTIFICATION_PHONE;
  }

  /**
   * Send notification with smart throttling
   */
  async send(
    type: NotificationType,
    data: any,
    options: {
      forceSend?: boolean;
      customPhone?: string;
    } = {}
  ): Promise<{ sent: boolean; reason?: string }> {
    const config = NOTIFICATION_TEMPLATES[type];
    
    if (!config) {
      logger.error('Unknown notification type', { type });
      return { sent: false, reason: 'Unknown type' };
    }

    // Check if should be throttled
    if (!options.forceSend && config.throttleMinutes) {
      const isThrottled = await this.checkThrottle(type, config.throttleMinutes);
      if (isThrottled) {
        logger.info('Notification throttled', { type });
        return { sent: false, reason: 'Throttled' };
      }
    }

    // For low priority, batch into digest unless forced
    if (!options.forceSend && config.priority === NotificationPriority.LOW && config.batchable) {
      await this.addToBatch(type, data);
      logger.info('Notification batched for digest', { type });
      return { sent: false, reason: 'Batched' };
    }

    // Send SMS
    const message = config.template(data);
    const phone = options.customPhone || this.phoneNumber;

    try {
      const result = await twilioClient.messages.create({
        body: message,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone
      });

      // Log notification
      await this.logNotification(type, data, message, result.sid, 'sent');

      // Update throttle
      if (config.throttleMinutes) {
        await this.setThrottle(type, config.throttleMinutes);
      }

      logger.info('SMS sent', { 
        type, 
        phone, 
        sid: result.sid,
        priority: config.priority 
      });

      return { sent: true };
    } catch (error) {
      logger.error('Failed to send SMS', { 
        type, 
        error: error.message 
      });
      
      await this.logNotification(type, data, message, null, 'failed', error.message);
      
      return { sent: false, reason: error.message };
    }
  }

  /**
   * Check if notification should be throttled
   */
  private async checkThrottle(type: NotificationType, minutes: number): Promise<boolean> {
    const key = `throttle:${type}`;
    const exists = await redis.get(key);
    return exists !== null;
  }

  /**
   * Set throttle for notification type
   */
  private async setThrottle(type: NotificationType, minutes: number): Promise<void> {
    const key = `throttle:${type}`;
    await redis.setex(key, minutes * 60, '1');
  }

  /**
   * Add notification to batch for digest
   */
  private async addToBatch(type: NotificationType, data: any): Promise<void> {
    const today = new Date().toISOString().split('T')[0];
    const batchKey = `batch:${today}`;
    
    await redis.lpush(batchKey, JSON.stringify({ type, data, timestamp: new Date() }));
    await redis.expire(batchKey, 86400 * 2); // Keep for 2 days
  }

  /**
   * Get batched notifications for digest
   */
  private async getBatchedNotifications(): Promise<any[]> {
    const today = new Date().toISOString().split('T')[0];
    const batchKey = `batch:${today}`;
    
    const items = await redis.lrange(batchKey, 0, -1);
    return items.map(item => JSON.parse(item));
  }

  /**
   * Send daily digest
   */
  async sendDailyDigest(): Promise<void> {
    logger.info('Generating daily digest');
    
    const batched = await this.getBatchedNotifications();
    
    // Get stats from database
    const today = new Date().toISOString().split('T')[0];
    const statsSnapshot = await db.collection('estimates')
      .where('date', '==', today)
      .get();

    const stats = {
      processed: statsSnapshot.size,
      autoSent: 0,
      needReview: 0,
      errors: 0,
      cost: 0
    };

    statsSnapshot.docs.forEach(doc => {
      const data = doc.data();
      if (data.status === 'auto-sent') stats.autoSent++;
      if (data.status === 'pending_review') stats.needReview++;
      if (data.status === 'error') stats.errors++;
    });

    // Get cost from API tracking
    const costDoc = await db.collection('api_usage')
      .where('date', '==', today)
      .get();
    
    costDoc.docs.forEach(doc => {
      stats.cost += doc.data().cost || 0;
    });

    const digestData = {
      ...stats,
      dashboardUrl: process.env.DASHBOARD_URL || 'https://your-dashboard.com'
    };

    await this.send(NotificationType.DAILY_DIGEST, digestData, { forceSend: true });

    // Clear batch after sending
    const batchKey = `batch:${today}`;
    await redis.del(batchKey);
  }

  /**
   * Log notification to database
   */
  private async logNotification(
    type: NotificationType,
    data: any,
    message: string,
    sid: string | null,
    status: 'sent' | 'failed' | 'batched',
    error?: string
  ): Promise<void> {
    await db.collection('notifications').add({
      type,
      data,
      message,
      sid,
      status,
      error,
      timestamp: new Date()
    });
  }

  /**
   * Get notification history
   */
  async getHistory(limit: number = 50): Promise<any[]> {
    const snapshot = await db.collection('notifications')
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .get();

    return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
  }

  /**
   * Get notification stats
   */
  async getStats(days: number = 7): Promise<any> {
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    
    const snapshot = await db.collection('notifications')
      .where('timestamp', '>=', startDate)
      .get();

    const stats = {
      total: snapshot.size,
      sent: 0,
      failed: 0,
      batched: 0,
      byType: {}
    };

    snapshot.docs.forEach(doc => {
      const data = doc.data();
      if (data.status === 'sent') stats.sent++;
      if (data.status === 'failed') stats.failed++;
      if (data.status === 'batched') stats.batched++;

      if (!stats.byType[data.type]) {
        stats.byType[data.type] = 0;
      }
      stats.byType[data.type]++;
    });

    return stats;
  }
}

// ===================================================================
// NOTIFICATION RULES ENGINE
// ===================================================================

export class NotificationRules {
  private notificationService: NotificationService;

  constructor(notificationService: NotificationService) {
    this.notificationService = notificationService;
  }

  /**
   * Handle estimate needs review
   */
  async onEstimateNeedsReview(estimate: any): Promise<void> {
    const data = {
      clientEmail: estimate.clientEmail,
      confidence: estimate.confidence,
      issues: estimate.issues,
      reviewUrl: `${process.env.DASHBOARD_URL}/review/${estimate.id}`
    };

    await this.notificationService.send(
      NotificationType.ESTIMATE_NEEDS_REVIEW,
      data
    );
  }

  /**
   * Handle estimate auto-sent
   */
  async onEstimateAutoSent(estimate: any): Promise<void> {
    const data = {
      clientEmail: estimate.clientEmail,
      amount: estimate.estimate.total,
      reference: estimate.reference
    };

    await this.notificationService.send(
      NotificationType.ESTIMATE_AUTO_SENT,
      data
    );
  }

  /**
   * Handle cost threshold
   */
  async onCostThreshold(current: number, limit: number, percentage: number): Promise<void> {
    const data = { current, limit, percentage };

    // Send at 50%, 75%, 90% thresholds
    if (percentage >= 90) {
      await this.notificationService.send(
        NotificationType.COST_THRESHOLD,
        data,
        { forceSend: true }
      );
    } else if (percentage >= 75 || percentage >= 50) {
      await this.notificationService.send(
        NotificationType.COST_THRESHOLD,
        data
      );
    }
  }

  /**
   * Handle daily budget exceeded
   */
  async onBudgetExceeded(spent: number, budget: number): Promise<void> {
    await this.notificationService.send(
      NotificationType.DAILY_BUDGET_EXCEEDED,
      { spent, budget },
      { forceSend: true }
    );
  }

  /**
   * Handle rate limit warning
   */
  async onRateLimitWarning(provider: string, warnings: string[]): Promise<void> {
    await this.notificationService.send(
      NotificationType.RATE_LIMIT_WARNING,
      { provider, warnings }
    );
  }

  /**
   * Handle system error
   */
  async onSystemError(service: string, error: string): Promise<void> {
    await this.notificationService.send(
      NotificationType.SYSTEM_ERROR,
      { service, error },
      { forceSend: true }
    );
  }

  /**
   * Handle authentication failure
   */
  async onAuthFailure(platform: string): Promise<void> {
    await this.notificationService.send(
      NotificationType.AUTHENTICATION_FAILURE,
      { 
        platform,
        dashboardUrl: `${process.env.DASHBOARD_URL}/settings/credentials`
      },
      { forceSend: true }
    );
  }
}

// ===================================================================
// SCHEDULED TASKS
// ===================================================================

export class NotificationScheduler {
  private notificationService: NotificationService;

  constructor(notificationService: NotificationService) {
    this.notificationService = notificationService;
  }

  /**
   * Schedule daily digest (run at 8 AM)
   */
  async scheduleDailyDigest(): Promise<void> {
    const now = new Date();
    const hour = now.getHours();

    // Send at 8 AM
    if (hour === 8) {
      await this.notificationService.sendDailyDigest();
    }
  }

  /**
   * Check cost thresholds (run every hour)
   */
  async checkCostThresholds(): Promise<void> {
    const today = new Date().toISOString().split('T')[0];
    const costKey = `cost:${today}`;
    const currentCost = parseFloat(await redis.get(costKey)) || 0;
    const dailyLimit = 10.00; // $10 daily limit

    const percentage = (currentCost / dailyLimit) * 100;

    if (percentage >= 100) {
      const rules = new NotificationRules(this.notificationService);
      await rules.onBudgetExceeded(currentCost, dailyLimit);
    } else if (percentage >= 50) {
      const rules = new NotificationRules(this.notificationService);
      await rules.onCostThreshold(currentCost, dailyLimit, percentage);
    }
  }
}

// ===================================================================
// REST API
// ===================================================================

const app = express();
app.use(express.json());

const notificationService = new NotificationService();
const notificationRules = new NotificationRules(notificationService);

// Send notification
app.post('/api/notify', async (req, res) => {
  try {
    const { type, data, forceSend } = req.body;
    
    const result = await notificationService.send(type, data, { forceSend });
    
    res.json(result);
  } catch (error) {
    logger.error('Error sending notification', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Get notification history
app.get('/api/notify/history', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit as string) || 50;
    const history = await notificationService.getHistory(limit);
    
    res.json(history);
  } catch (error) {
    logger.error('Error fetching history', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Get notification stats
app.get('/api/notify/stats', async (req, res) => {
  try {
    const days = parseInt(req.query.days as string) || 7;
    const stats = await notificationService.getStats(days);
    
    res.json(stats);
  } catch (error) {
    logger.error('Error fetching stats', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Send daily digest manually
app.post('/api/notify/digest', async (req, res) => {
  try {
    await notificationService.sendDailyDigest();
    res.json({ success: true });
  } catch (error) {
    logger.error('Error sending digest', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Update notification preferences
app.post('/api/notify/preferences', async (req, res) => {
  try {
    const { phoneNumber, types } = req.body;
    
    await db.collection('config').doc('notification_preferences').set({
      phoneNumber,
      enabledTypes: types,
      updatedAt: new Date()
    });

    logger.info('Notification preferences updated', { phoneNumber, types });
    res.json({ success: true });
  } catch (error) {
    logger.error('Error updating preferences', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Test notification
app.post('/api/notify/test', async (req, res) => {
  try {
    const result = await notificationService.send(
      NotificationType.DAILY_DIGEST,
      {
        processed: 5,
        autoSent: 3,
        needReview: 2,
        errors: 0,
        cost: 2.50,
        dashboardUrl: process.env.DASHBOARD_URL
      },
      { forceSend: true }
    );
    
    res.json(result);
  } catch (error) {
    logger.error('Error sending test notification', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Export services
export { 