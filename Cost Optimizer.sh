// ===================================================================
// COST OPTIMIZER & BUDGET MANAGEMENT MODULE
// Intelligently manages costs, predicts spending, auto-adjusts usage
// ===================================================================

import express from 'express';
import { Firestore } from '@google-cloud/firestore';
import winston from 'winston';
import Redis from 'ioredis';
import cron from 'node-cron';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'cost-optimizer.log' })
  ]
});

const db = new Firestore();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// ===================================================================
// COST OPTIMIZATION ENGINE
// ===================================================================

interface BudgetConfig {
  dailyLimit: number;
  monthlyLimit: number;
  warningThresholds: number[]; // [50, 75, 90]
  autoThrottle: boolean;
  priorityMode: 'cost' | 'speed' | 'balanced';
}

export class CostOptimizer {
  private budget: BudgetConfig = {
    dailyLimit: 10.00,
    monthlyLimit: 300.00,
    warningThresholds: [50, 75, 90],
    autoThrottle: true,
    priorityMode: 'balanced'
  };

  /**
   * SMART MODEL SELECTION - Choose cheapest model that meets requirements
   */
  async selectOptimalModel(task: {
    type: 'email_analysis' | 'pdf_analysis' | 'estimation' | 'simple_extraction';
    complexity: 'low' | 'medium' | 'high';
    requiresVision: boolean;
    maxBudget?: number;
  }): Promise<{ model: string; estimatedCost: number; reasoning: string }> {
    
    const models = {
      'gemini-2.0-flash-exp': { 
        inputCost: 0.075 / 1_000_000, 
        outputCost: 0.30 / 1_000_000,
        speed: 'fast',
        capability: ['text', 'vision'],
        avgTokens: { low: 500, medium: 2000, high: 5000 }
      },
      'gemini-1.5-flash': { 
        inputCost: 0.075 / 1_000_000, 
        outputCost: 0.30 / 1_000_000,
        speed: 'fast',
        capability: ['text'],
        avgTokens: { low: 400, medium: 1500, high: 4000 }
      },
      'gemini-1.5-pro': { 
        inputCost: 1.25 / 1_000_000, 
        outputCost: 5.00 / 1_000_000,
        speed: 'medium',
        capability: ['text', 'vision'],
        avgTokens: { low: 600, medium: 2500, high: 8000 }
      }
    };

    // Filter models by requirements
    let candidates = Object.entries(models).filter(([_, config]) => {
      if (task.requiresVision && !config.capability.includes('vision')) return false;
      return true;
    });

    // Calculate estimated costs
    const estimates = candidates.map(([model, config]) => {
      const tokens = config.avgTokens[task.complexity];
      const cost = (tokens * config.inputCost) + (tokens * 0.3 * config.outputCost);
      
      return { model, cost, config };
    });

    // Sort by cost
    estimates.sort((a, b) => a.cost - b.cost);

    // Check if within budget
    if (task.maxBudget && estimates[0].cost > task.maxBudget) {
      throw new Error(`No model available within budget $${task.maxBudget}`);
    }

    // Select based on priority mode
    let selected = estimates[0];
    
    if (this.budget.priorityMode === 'speed' && task.complexity === 'high') {
      // For high complexity + speed priority, use faster model even if slightly more expensive
      selected = estimates.find(e => e.config.speed === 'fast') || selected;
    }

    logger.info('Model selected', { 
      model: selected.model, 
      estimatedCost: selected.cost.toFixed(6),
      task: task.type 
    });

    return {
      model: selected.model,
      estimatedCost: selected.cost,
      reasoning: `Selected ${selected.model} for ${task.type} (${task.complexity} complexity) - estimated $${selected.cost.toFixed(6)}`
    };
  }

  /**
   * CACHING STRATEGY - Avoid duplicate API calls
   */
  async shouldUseCache(operation: string, params: any): Promise<boolean> {
    const cacheKey = this.generateCacheKey(operation, params);
    const cached = await redis.get(cacheKey);
    
    if (cached) {
      logger.info('Cache hit - saved API call', { operation });
      
      // Track cost savings
      await this.trackCostSaving(operation, 'cache_hit');
      return true;
    }
    
    return false;
  }

  async setCacheResult(operation: string, params: any, result: any, ttl: number = 3600): Promise<void> {
    const cacheKey = this.generateCacheKey(operation, params);
    await redis.setex(cacheKey, ttl, JSON.stringify(result));
  }

  private generateCacheKey(operation: string, params: any): string {
    const crypto = require('crypto');
    const hash = crypto.createHash('md5').update(JSON.stringify(params)).digest('hex');
    return `cache:${operation}:${hash}`;
  }

  /**
   * BATCH PROCESSING - Reduce per-call overhead
   */
  async batchAPIRequests(requests: any[]): Promise<any[]> {
    // Group similar requests
    const grouped = this.groupSimilarRequests(requests);
    
    const results = [];
    for (const group of grouped) {
      // Process group with single API call if possible
      if (group.length > 1 && this.canBatchProcess(group)) {
        logger.info('Batching requests', { count: group.length });
        const batchResult = await this.processBatch(group);
        results.push(...batchResult);
        
        await this.trackCostSaving('batch_processing', `${group.length}_requests`);
      } else {
        // Process individually
        for (const req of group) {
          results.push(await this.processSingle(req));
        }
      }
    }
    
    return results;
  }

  private groupSimilarRequests(requests: any[]): any[][] {
    // Group by operation type
    const groups = {};
    requests.forEach(req => {
      const key = req.operation;
      if (!groups[key]) groups[key] = [];
      groups[key].push(req);
    });
    return Object.values(groups);
  }

  private canBatchProcess(requests: any[]): boolean {
    // Check if requests can be batched (same model, similar size)
    return requests.every(r => r.operation === requests[0].operation);
  }

  /**
   * BUDGET MONITORING & AUTO-THROTTLE
   */
  async checkBudgetAndThrottle(): Promise<{ 
    allowed: boolean; 
    reason?: string;
    waitTime?: number;
  }> {
    const today = new Date().toISOString().split('T')[0];
    const costKey = `cost:${today}`;
    const currentCost = parseFloat(await redis.get(costKey)) || 0;

    // Check daily budget
    const dailyPercentage = (currentCost / this.budget.dailyLimit) * 100;

    if (dailyPercentage >= 100) {
      logger.warn('Daily budget exceeded', { currentCost, limit: this.budget.dailyLimit });
      
      if (this.budget.autoThrottle) {
        // Calculate when budget resets (next day)
        const now = new Date();
        const tomorrow = new Date(now);
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);
        const waitTime = tomorrow.getTime() - now.getTime();
        
        return {
          allowed: false,
          reason: 'Daily budget exceeded',
          waitTime: Math.floor(waitTime / 1000)
        };
      }
    }

    // Throttle if approaching limit
    if (dailyPercentage >= 90 && this.budget.autoThrottle) {
      logger.info('Approaching budget limit - applying throttle');
      
      // Add delay between requests
      await new Promise(resolve => setTimeout(resolve, 5000)); // 5 sec delay
      
      return { 
        allowed: true, 
        reason: 'Throttled - 90% of daily budget used'
      };
    }

    return { allowed: true };
  }

  /**
   * COST PREDICTION & ALERTS
   */
  async predictDailyCost(): Promise<{
    predicted: number;
    confidence: number;
    willExceedBudget: boolean;
    recommendation: string;
  }> {
    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const currentHour = now.getHours();
    
    // Get cost so far today
    const costKey = `cost:${today}`;
    const costSoFar = parseFloat(await redis.get(costKey)) || 0;
    
    // Get hourly breakdown
    const hourlyCosts = [];
    for (let h = 0; h < currentHour; h++) {
      const hourKey = `cost:${today}:${h}`;
      const hourCost = parseFloat(await redis.get(hourKey)) || 0;
      hourlyCosts.push(hourCost);
    }
    
    // Calculate average hourly cost
    const avgHourlyCost = costSoFar / (currentHour || 1);
    
    // Predict remaining hours (assume 8 AM - 8 PM working hours)
    const workingHoursLeft = Math.max(0, 20 - currentHour);
    const predictedAdditional = avgHourlyCost * workingHoursLeft;
    const predictedTotal = costSoFar + predictedAdditional;
    
    // Confidence based on how much data we have
    const confidence = Math.min(currentHour / 12, 1); // Higher confidence as day progresses
    
    const willExceed = predictedTotal > this.budget.dailyLimit;
    
    let recommendation = '';
    if (willExceed) {
      const overage = predictedTotal - this.budget.dailyLimit;
      recommendation = `Predicted to exceed budget by $${overage.toFixed(2)}. Consider: ` +
                      `1) Enable caching, 2) Use cheaper models, 3) Batch requests`;
    } else {
      const remaining = this.budget.dailyLimit - predictedTotal;
      recommendation = `On track. $${remaining.toFixed(2)} budget remaining predicted.`;
    }
    
    logger.info('Cost prediction', { 
      costSoFar, 
      predictedTotal, 
      confidence: confidence.toFixed(2) 
    });
    
    return {
      predicted: predictedTotal,
      confidence,
      willExceedBudget: willExceed,
      recommendation
    };
  }

  /**
   * INTELLIGENT RETRY STRATEGY - Avoid costly retries
   */
  async shouldRetry(error: any, attemptCount: number, operation: string): Promise<{
    retry: boolean;
    delay: number;
    useAlternative: boolean;
  }> {
    // Don't retry if budget exhausted
    const budgetCheck = await this.checkBudgetAndThrottle();
    if (!budgetCheck.allowed) {
      return { retry: false, delay: 0, useAlternative: false };
    }

    // Rate limit errors - wait and retry
    if (error.message?.includes('rate limit')) {
      return { 
        retry: attemptCount < 3, 
        delay: Math.pow(2, attemptCount) * 1000,
        useAlternative: false
      };
    }

    // Server errors - try alternative model
    if (error.code >= 500 && attemptCount < 2) {
      logger.info('Server error - suggesting alternative model');
      return { 
        retry: true, 
        delay: 2000,
        useAlternative: true 
      };
    }

    // Client errors - don't retry
    if (error.code >= 400 && error.code < 500) {
      return { retry: false, delay: 0, useAlternative: false };
    }

    // Default: retry with exponential backoff
    return { 
      retry: attemptCount < 3, 
      delay: Math.min(Math.pow(2, attemptCount) * 1000, 30000),
      useAlternative: false
    };
  }

  /**
   * COST SAVING TRACKER
   */
  private async trackCostSaving(method: string, details: string): Promise<void> {
    await db.collection('cost_savings').add({
      method,
      details,
      timestamp: new Date(),
      date: new Date().toISOString().split('T')[0]
    });
  }

  async getCostSavings(days: number = 7): Promise<any> {
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    
    const snapshot = await db.collection('cost_savings')
      .where('timestamp', '>=', startDate)
      .get();
    
    const savings = { total: 0, byMethod: {} };
    
    snapshot.docs.forEach(doc => {
      const data = doc.data();
      savings.total++;
      
      if (!savings.byMethod[data.method]) {
        savings.byMethod[data.method] = 0;
      }
      savings.byMethod[data.method]++;
    });
    
    // Estimate dollar savings
    const estimatedSavings = {
      cache_hits: savings.byMethod['cache_hit'] ? savings.byMethod['cache_hit'] * 0.002 : 0,
      batch_processing: savings.byMethod['batch_processing'] ? savings.byMethod['batch_processing'] * 0.005 : 0,
      model_optimization: savings.byMethod['model_optimization'] ? savings.byMethod['model_optimization'] * 0.001 : 0
    };
    
    return {
      occurrences: savings.byMethod,
      estimatedDollarSavings: Object.values(estimatedSavings).reduce((a, b) => a + b, 0),
      breakdown: estimatedSavings
    };
  }

  /**
   * OPTIMIZATION RECOMMENDATIONS
   */
  async generateOptimizationReport(): Promise<any> {
    const last7Days = await this.getUsageStats(7);
    const savings = await this.getCostSavings(7);
    const prediction = await this.predictDailyCost();
    
    const recommendations = [];
    
    // High API usage without caching
    if (last7Days.totalCalls > 100 && (!savings.byMethod['cache_hit'] || savings.byMethod['cache_hit'] < 20)) {
      recommendations.push({
        priority: 'high',
        title: 'Enable Aggressive Caching',
        impact: '$5-10/week savings',
        action: 'Increase cache TTL from 1hr to 24hrs for PDF analysis',
        code: `await redis.setex(cacheKey, 86400, result); // 24 hours`
      });
    }
    
    // Using expensive models unnecessarily
    if (last7Days.byModel && last7Days.byModel['gemini-1.5-pro'] > 10) {
      recommendations.push({
        priority: 'high',
        title: 'Use Flash Model for Simple Tasks',
        impact: '$20-30/week savings',
        action: 'Switch email analysis to gemini-2.0-flash-exp',
        code: `selectOptimalModel({ type: 'email_analysis', complexity: 'low' })`
      });
    }
    
    // No batch processing
    if (!savings.byMethod['batch_processing']) {
      recommendations.push({
        priority: 'medium',
        title: 'Implement Batch Processing',
        impact: '$3-5/week savings',
        action: 'Process multiple emails in single API call',
        code: `batchAPIRequests(pendingEmails)`
      });
    }
    
    // Budget prediction
    if (prediction.willExceedBudget) {
      recommendations.push({
        priority: 'urgent',
        title: 'Budget Overrun Predicted',
        impact: `May exceed by $${(prediction.predicted - this.budget.dailyLimit).toFixed(2)}`,
        action: 'Enable auto-throttle or increase budget',
        code: `budget.autoThrottle = true`
      });
    }
    
    return {
      summary: {
        currentDailyCost: last7Days.avgDailyCost,
        potentialSavings: savings.estimatedDollarSavings * 4, // Monthly
        efficiencyScore: this.calculateEfficiencyScore(last7Days, savings)
      },
      recommendations
    };
  }

  private calculateEfficiencyScore(usage: any, savings: any): number {
    // Score from 0-100 based on cost optimization
    let score = 50; // Base score
    
    // Bonus for cache usage
    if (savings.byMethod['cache_hit']) {
      score += Math.min((savings.byMethod['cache_hit'] / usage.totalCalls) * 30, 30);
    }
    
    // Bonus for batch processing
    if (savings.byMethod['batch_processing']) {
      score += 10;
    }
    
    // Penalty for expensive model overuse
    if (usage.byModel && usage.byModel['gemini-1.5-pro'] > usage.totalCalls * 0.3) {
      score -= 15;
    }
    
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  private async getUsageStats(days: number): Promise<any> {
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const snapshot = await db.collection('api_usage')
      .where('timestamp', '>=', startDate)
      .get();

    const stats = { totalCalls: 0, totalCost: 0, byModel: {}, avgDailyCost: 0 };
    snapshot.docs.forEach(doc => {
      const data = doc.data();
      stats.totalCalls++;
      stats.totalCost += data.cost || 0;
      if (data.model) {
        stats.byModel[data.model] = (stats.byModel[data.model] || 0) + 1;
      }
    });
    stats.avgDailyCost = stats.totalCost / days;
    return stats;
  }

  // Stub methods for example
  private async processBatch(group: any[]): Promise<any[]> { return []; }
  private async processSingle(req: any): Promise<any> { return {}; }
}

// ===================================================================
// REST API
// ===================================================================

const app = express();
app.use(express.json());

const optimizer = new CostOptimizer();

// Get optimization report
app.get('/api/optimize/report', async (req, res) => {
  try {
    const report = await optimizer.generateOptimizationReport();
    res.json(report);
  } catch (error) {
    logger.error('Error generating report', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Select optimal model
app.post('/api/optimize/select-model', async (req, res) => {
  try {
    const selection = await optimizer.selectOptimalModel(req.body);
    res.json(selection);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Check budget status
app.get('/api/optimize/budget-check', async (req, res) => {
  try {
    const check = await optimizer.checkBudgetAndThrottle();
    const prediction = await optimizer.predictDailyCost();
    res.json({ check, prediction });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get cost savings
app.get('/api/optimize/savings', async (req, res) => {
  try {
    const days = parseInt(req.query.days as string) || 7;
    const savings = await optimizer.getCostSavings(days);
    res.json(savings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export { optimizer };

if (require.main === module) {
  const PORT = process.env.COST_OPTIMIZER_PORT || 8084;
  app.listen(PORT, () => {
    logger.info(`Cost Optimizer running on port ${PORT}`);
    
    // Auto-check budget every hour
    cron.schedule('0 * * * *', async () => {
      const check = await optimizer.checkBudgetAndThrottle();
      logger.info('Hourly budget check', check);
    });
  });
}

export default app;