// ===================================================================
// API USAGE TRACKING & COST MANAGEMENT MODULE
// Tracks all API calls, costs, and enforces rate limits
// ===================================================================

import express from 'express';
import { Firestore, FieldValue } from '@google-cloud/firestore';
import winston from 'winston';
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
    new winston.transports.File({ filename: 'api-tracking.log' })
  ]
});

const db = new Firestore();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// API Cost Structure (as of 2025)
const API_COSTS = {
  gemini: {
    'gemini-2.0-flash-exp': {
      input: 0.075 / 1_000_000,  // per token
      output: 0.30 / 1_000_000,
      cached_input: 0.01875 / 1_000_000
    },
    'gemini-1.5-pro': {
      input: 1.25 / 1_000_000,
      output: 5.00 / 1_000_000
    }
  },
  gmail: {
    api_call: 0,  // Free
    storage: 0    // Free for reasonable use
  },
  puppeteer: {
    compute_minute: 0.05  // Estimated Cloud Run cost
  }
};

// Rate Limits
const RATE_LIMITS = {
  gemini: {
    requestsPerMinute: 60,
    tokensPerMinute: 4_000_000,
    requestsPerDay: 1500
  },
  gmail: {
    requestsPerMinute: 250,
    requestsPerDay: 10000
  },
  overall: {
    maxDailyCost: 10.00  // $10/day budget
  }
};

// ===================================================================
// API TRACKING SERVICE
// ===================================================================

export class APITracker {
  private serviceName: string;

  constructor(serviceName: string = 'estimate-agent') {
    this.serviceName = serviceName;
  }

  /**
   * Track an API call with automatic cost calculation
   */
  async trackAPICall(params: {
    provider: string;
    model?: string;
    operation: string;
    inputTokens?: number;
    outputTokens?: number;
    cachedTokens?: number;
    duration?: number;
    status: 'success' | 'error';
    error?: string;
    metadata?: any;
  }): Promise<void> {
    const timestamp = new Date();
    const cost = this.calculateCost(params);

    const record = {
      serviceName: this.serviceName,
      provider: params.provider,
      model: params.model,
      operation: params.operation,
      inputTokens: params.inputTokens || 0,
      outputTokens: params.outputTokens || 0,
      cachedTokens: params.cachedTokens || 0,
      totalTokens: (params.inputTokens || 0) + (params.outputTokens || 0),
      duration: params.duration || 0,
      cost: cost,
      status: params.status,
      error: params.error,
      metadata: params.metadata,
      timestamp,
      date: timestamp.toISOString().split('T')[0]
    };

    // Store in Firestore
    await db.collection('api_usage').add(record);

    // Update real-time counters in Redis
    await this.updateRedisCounters(params.provider, cost, params.inputTokens + params.outputTokens);

    // Check rate limits
    await this.checkRateLimits(params.provider);

    logger.info('API call tracked', { 
      provider: params.provider,
      operation: params.operation,
      cost: cost.toFixed(4),
      status: params.status
    });
  }

  /**
   * Calculate cost based on usage
   */
  private calculateCost(params: any): number {
    if (params.provider === 'gemini' && params.model) {
      const pricing = API_COSTS.gemini[params.model];
      if (!pricing) return 0;

      let cost = 0;
      cost += (params.inputTokens || 0) * pricing.input;
      cost += (params.outputTokens || 0) * pricing.output;
      if (params.cachedTokens && pricing.cached_input) {
        cost += params.cachedTokens * pricing.cached_input;
      }
      return cost;
    }

    if (params.provider === 'puppeteer') {
      const minutes = (params.duration || 0) / 60000;
      return minutes * API_COSTS.puppeteer.compute_minute;
    }

    return 0;
  }

  /**
   * Update Redis counters for real-time tracking
   */
  private async updateRedisCounters(provider: string, cost: number, tokens: number): Promise<void> {
    const now = new Date();
    const minuteKey = `rate:${provider}:${now.getFullYear()}-${now.getMonth()}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
    const dayKey = `rate:${provider}:${now.toISOString().split('T')[0]}`;
    const costDayKey = `cost:${now.toISOString().split('T')[0]}`;

    const pipeline = redis.pipeline();
    
    // Increment counters
    pipeline.incr(`${minuteKey}:requests`);
    pipeline.incrby(`${minuteKey}:tokens`, tokens);
    pipeline.incr(`${dayKey}:requests`);
    pipeline.incrby(`${dayKey}:tokens`, tokens);
    pipeline.incrbyfloat(costDayKey, cost);

    // Set expiry (keep for 7 days)
    pipeline.expire(`${minuteKey}:requests`, 604800);
    pipeline.expire(`${minuteKey}:tokens`, 604800);
    pipeline.expire(`${dayKey}:requests`, 604800);
    pipeline.expire(`${dayKey}:tokens`, 604800);
    pipeline.expire(costDayKey, 604800);

    await pipeline.exec();
  }

  /**
   * Check if rate limits are exceeded
   */
  private async checkRateLimits(provider: string): Promise<void> {
    const now = new Date();
    const minuteKey = `rate:${provider}:${now.getFullYear()}-${now.getMonth()}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
    const dayKey = `rate:${provider}:${now.toISOString().split('T')[0]}`;
    const costDayKey = `cost:${now.toISOString().split('T')[0]}`;

    const [requestsPerMin, tokensPerMin, requestsPerDay, tokensPerDay, costToday] = await Promise.all([
      redis.get(`${minuteKey}:requests`),
      redis.get(`${minuteKey}:tokens`),
      redis.get(`${dayKey}:requests`),
      redis.get(`${dayKey}:tokens`),
      redis.get(costDayKey)
    ]);

    const limits = RATE_LIMITS[provider] || {};
    const warnings = [];

    // Check per-minute limits
    if (limits.requestsPerMinute && parseInt(requestsPerMin) > limits.requestsPerMinute) {
      warnings.push(`Rate limit exceeded: ${requestsPerMin} requests/min (limit: ${limits.requestsPerMinute})`);
    }

    if (limits.tokensPerMinute && parseInt(tokensPerMin) > limits.tokensPerMinute) {
      warnings.push(`Token limit exceeded: ${tokensPerMin} tokens/min (limit: ${limits.tokensPerMinute})`);
    }

    // Check daily limits
    if (limits.requestsPerDay && parseInt(requestsPerDay) > limits.requestsPerDay) {
      warnings.push(`Daily request limit exceeded: ${requestsPerDay} requests (limit: ${limits.requestsPerDay})`);
    }

    // Check cost budget
    const dailyCost = parseFloat(costToday) || 0;
    if (dailyCost > RATE_LIMITS.overall.maxDailyCost) {
      warnings.push(`Daily cost budget exceeded: $${dailyCost.toFixed(2)} (limit: $${RATE_LIMITS.overall.maxDailyCost})`);
    }

    if (warnings.length > 0) {
      logger.warn('Rate limit warnings', { provider, warnings });
      
      // Store alert
      await db.collection('alerts').add({
        type: 'rate_limit',
        provider,
        warnings,
        timestamp: new Date()
      });
    }
  }

  /**
   * Get usage statistics
   */
  async getUsageStats(dateRange: { start: Date; end: Date }): Promise<any> {
    const snapshot = await db.collection('api_usage')
      .where('timestamp', '>=', dateRange.start)
      .where('timestamp', '<=', dateRange.end)
      .get();

    const stats = {
      totalCalls: 0,
      totalCost: 0,
      totalTokens: 0,
      byProvider: {},
      byModel: {},
      byOperation: {},
      errors: 0
    };

    snapshot.docs.forEach(doc => {
      const data = doc.data();
      stats.totalCalls++;
      stats.totalCost += data.cost || 0;
      stats.totalTokens += data.totalTokens || 0;

      if (data.status === 'error') stats.errors++;

      // Aggregate by provider
      if (!stats.byProvider[data.provider]) {
        stats.byProvider[data.provider] = { calls: 0, cost: 0, tokens: 0 };
      }
      stats.byProvider[data.provider].calls++;
      stats.byProvider[data.provider].cost += data.cost || 0;
      stats.byProvider[data.provider].tokens += data.totalTokens || 0;

      // Aggregate by model
      if (data.model) {
        if (!stats.byModel[data.model]) {
          stats.byModel[data.model] = { calls: 0, cost: 0, tokens: 0 };
        }
        stats.byModel[data.model].calls++;
        stats.byModel[data.model].cost += data.cost || 0;
        stats.byModel[data.model].tokens += data.totalTokens || 0;
      }

      // Aggregate by operation
      if (!stats.byOperation[data.operation]) {
        stats.byOperation[data.operation] = { calls: 0, cost: 0 };
      }
      stats.byOperation[data.operation].calls++;
      stats.byOperation[data.operation].cost += data.cost || 0;
    });

    return stats;
  }

  /**
   * Get current rate limit status
   */
  async getRateLimitStatus(): Promise<any> {
    const now = new Date();
    const minuteKey = `rate:gemini:${now.getFullYear()}-${now.getMonth()}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
    const dayKey = `rate:gemini:${now.toISOString().split('T')[0]}`;
    const costDayKey = `cost:${now.toISOString().split('T')[0]}`;

    const [requestsPerMin, tokensPerMin, requestsPerDay, tokensPerDay, costToday] = await Promise.all([
      redis.get(`${minuteKey}:requests`),
      redis.get(`${minuteKey}:tokens`),
      redis.get(`${dayKey}:requests`),
      redis.get(`${dayKey}:tokens`),
      redis.get(costDayKey)
    ]);

    return {
      currentMinute: {
        requests: parseInt(requestsPerMin) || 0,
        limit: RATE_LIMITS.gemini.requestsPerMinute,
        tokens: parseInt(tokensPerMin) || 0,
        tokenLimit: RATE_LIMITS.gemini.tokensPerMinute
      },
      today: {
        requests: parseInt(requestsPerDay) || 0,
        limit: RATE_LIMITS.gemini.requestsPerDay,
        tokens: parseInt(tokensPerDay) || 0,
        cost: parseFloat(costToday) || 0,
        costLimit: RATE_LIMITS.overall.maxDailyCost
      }
    };
  }

  /**
   * Generate cost projection
   */
  async projectMonthlyCost(): Promise<any> {
    const last7Days = await this.getUsageStats({
      start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      end: new Date()
    });

    const avgDailyCost = last7Days.totalCost / 7;
    const projectedMonthlyCost = avgDailyCost * 30;

    return {
      last7DaysCost: last7Days.totalCost,
      avgDailyCost,
      projectedMonthlyCost,
      breakdown: last7Days.byProvider
    };
  }
}

// ===================================================================
// MIDDLEWARE FOR AUTOMATIC TRACKING
// ===================================================================

export function createTrackingMiddleware(tracker: APITracker) {
  return {
    /**
     * Wrap Gemini API calls with tracking
     */
    wrapGeminiCall: (model: string) => {
      return async (operation: string, fn: Function) => {
        const startTime = Date.now();
        let status: 'success' | 'error' = 'success';
        let error: string | undefined;
        let result: any;

        try {
          result = await fn();
          
          // Extract token usage from result
          const inputTokens = result.usageMetadata?.promptTokenCount || 0;
          const outputTokens = result.usageMetadata?.candidatesTokenCount || 0;
          const cachedTokens = result.usageMetadata?.cachedContentTokenCount || 0;

          await tracker.trackAPICall({
            provider: 'gemini',
            model,
            operation,
            inputTokens,
            outputTokens,
            cachedTokens,
            duration: Date.now() - startTime,
            status: 'success'
          });

          return result;
        } catch (err) {
          status = 'error';
          error = err.message;
          throw err;
        } finally {
          if (status === 'error') {
            await tracker.trackAPICall({
              provider: 'gemini',
              model,
              operation,
              duration: Date.now() - startTime,
              status,
              error
            });
          }
        }
      };
    },

    /**
     * Wrap Gmail API calls with tracking
     */
    wrapGmailCall: () => {
      return async (operation: string, fn: Function) => {
        const startTime = Date.now();
        
        try {
          const result = await fn();
          
          await tracker.trackAPICall({
            provider: 'gmail',
            operation,
            duration: Date.now() - startTime,
            status: 'success'
          });

          return result;
        } catch (err) {
          await tracker.trackAPICall({
            provider: 'gmail',
            operation,
            duration: Date.now() - startTime,
            status: 'error',
            error: err.message
          });
          throw err;
        }
      };
    },

    /**
     * Wrap Puppeteer sessions with tracking
     */
    wrapPuppeteerSession: () => {
      return async (operation: string, fn: Function) => {
        const startTime = Date.now();
        
        try {
          const result = await fn();
          
          await tracker.trackAPICall({
            provider: 'puppeteer',
            operation,
            duration: Date.now() - startTime,
            status: 'success'
          });

          return result;
        } catch (err) {
          await tracker.trackAPICall({
            provider: 'puppeteer',
            operation,
            duration: Date.now() - startTime,
            status: 'error',
            error: err.message
          });
          throw err;
        }
      };
    }
  };
}

// ===================================================================
// REST API
// ===================================================================

const app = express();
app.use(express.json());

const tracker = new APITracker();

// Get usage stats
app.get('/api/usage/stats', async (req, res) => {
  try {
    const days = parseInt(req.query.days as string) || 7;
    const stats = await tracker.getUsageStats({
      start: new Date(Date.now() - days * 24 * 60 * 60 * 1000),
      end: new Date()
    });

    res.json(stats);
  } catch (error) {
    logger.error('Error fetching usage stats', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Get rate limit status
app.get('/api/usage/rate-limits', async (req, res) => {
  try {
    const status = await tracker.getRateLimitStatus();
    res.json(status);
  } catch (error) {
    logger.error('Error fetching rate limits', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Get cost projection
app.get('/api/usage/projection', async (req, res) => {
  try {
    const projection = await tracker.projectMonthlyCost();
    res.json(projection);
  } catch (error) {
    logger.error('Error calculating projection', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Get alerts
app.get('/api/usage/alerts', async (req, res) => {
  try {
    const snapshot = await db.collection('alerts')
      .orderBy('timestamp', 'desc')
      .limit(50)
      .get();

    const alerts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(alerts);
  } catch (error) {
    logger.error('Error fetching alerts', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Update rate limits
app.post('/api/usage/limits', async (req, res) => {
  try {
    const { provider, limits } = req.body;
    
    await db.collection('config').doc(`rate_limits_${provider}`).set({
      ...limits,
      updatedAt: new Date()
    });

    // Update in-memory limits
    RATE_LIMITS[provider] = { ...RATE_LIMITS[provider], ...limits };

    logger.info('Rate limits updated', { provider, limits });
    res.json({ success: true });
  } catch (error) {
    logger.error('Error updating limits', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Export tracker instance
export { tracker };

// Start server if run directly
if (require.main === module) {
  const PORT = process.env.API_TRACKING_PORT || 8081;
  app.listen(PORT, () => {
    logger.info(`API Tracking Service running on port ${PORT}`);
  });
}

export default app;