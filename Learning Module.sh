// ===================================================================
// AGENT LEARNING & CONTEXT ENHANCEMENT MODULE
// Enables agents to learn from feedback and improve over time
// ===================================================================

import express from 'express';
import { Firestore } from '@google-cloud/firestore';
import { GoogleGenerativeAI } from '@google/generative-ai';
import winston from 'winston';
import Redis from 'ioredis';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'agent-learning.log' })
  ]
});

const db = new Firestore();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_API_KEY);

// ===================================================================
// CONTEXT MEMORY SYSTEM
// ===================================================================

export class AgentMemory {
  /**
   * Build rich context from historical data for agent
   */
  async buildContextForEstimate(emailData: any): Promise<string> {
    const contexts = await Promise.all([
      this.getClientHistory(emailData.from),
      this.getSimilarProjects(emailData),
      this.getRecentFeedback(),
      this.getSuccessPatterns(),
      this.getPricingAdjustments()
    ]);

    const contextPrompt = `
AGENT CONTEXT - Use this historical knowledge to improve your response:

CLIENT HISTORY:
${contexts[0]}

SIMILAR PAST PROJECTS:
${contexts[1]}

RECENT FEEDBACK & LESSONS:
${contexts[2]}

SUCCESS PATTERNS:
${contexts[3]}

PRICING ADJUSTMENTS:
${contexts[4]}

IMPORTANT: Apply these learnings to provide a better estimate.
- If client has history, acknowledge it
- If similar projects exist, use their data for validation
- If feedback indicates issues, avoid those mistakes
- Follow successful patterns from past estimates
`;

    return contextPrompt;
  }

  /**
   * Get client interaction history
   */
  private async getClientHistory(clientEmail: string): Promise<string> {
    const snapshot = await db.collection('estimates')
      .where('clientEmail', '==', clientEmail)
      .orderBy('createdAt', 'desc')
      .limit(5)
      .get();

    if (snapshot.empty) {
      return '- New client, no previous history';
    }

    const history = snapshot.docs.map(doc => {
      const data = doc.data();
      return `
- Previous project: ${data.projectName || 'Unnamed'} (${new Date(data.createdAt.toDate()).toLocaleDateString()})
  Estimated: $${data.estimate?.total?.toFixed(2) || 'N/A'}
  Status: ${data.status}
  ${data.actualCost ? `Actual cost: $${data.actualCost.toFixed(2)} (${Math.abs(((data.actualCost - data.estimate.total) / data.estimate.total) * 100).toFixed(1)}% variance)` : ''}
  ${data.clientFeedback ? `Feedback: "${data.clientFeedback}"` : ''}`;
    });

    const wonProjects = snapshot.docs.filter(d => d.data().status === 'won').length;
    const avgEstimate = snapshot.docs.reduce((sum, d) => sum + (d.data().estimate?.total || 0), 0) / snapshot.size;

    return `
Client: ${clientEmail}
Total projects: ${snapshot.size}
Won: ${wonProjects} (${((wonProjects / snapshot.size) * 100).toFixed(0)}% conversion)
Average project value: $${avgEstimate.toFixed(2)}

${history.join('\n')}

INSIGHT: ${this.generateClientInsight(snapshot.docs)}
`;
  }

  private generateClientInsight(docs: any[]): string {
    const data = docs.map(d => d.data());
    const avgVariance = data
      .filter(d => d.actualCost)
      .reduce((sum, d) => sum + Math.abs((d.actualCost - d.estimate.total) / d.estimate.total), 0) / data.length;

    if (avgVariance > 0.15) {
      return 'Historical estimates for this client tend to be off by >15%. Be extra careful with measurements.';
    }
    
    const quickResponder = data.every(d => d.responseTime && d.responseTime < 48);
    if (quickResponder) {
      return 'This client responds quickly. They value fast turnaround.';
    }

    const priceConscious = data.filter(d => d.status === 'lost').length > data.filter(d => d.status === 'won').length;
    if (priceConscious) {
      return 'Price-conscious client. Consider competitive pricing or highlight value-adds.';
    }

    return 'Reliable client with consistent project patterns.';
  }

  /**
   * Find similar past projects for validation
   */
  private async getSimilarProjects(emailData: any): Promise<string> {
    // Extract project characteristics
    const keywords = this.extractKeywords(emailData.subject + ' ' + emailData.body);
    
    // Query Firestore for similar projects
    const snapshot = await db.collection('estimates')
      .where('status', 'in', ['won', 'completed'])
      .orderBy('createdAt', 'desc')
      .limit(50)
      .get();

    // Score similarity
    const similar = snapshot.docs
      .map(doc => {
        const data = doc.data();
        const docKeywords = this.extractKeywords(data.projectName || '' + data.notes || '');
        const similarity = this.calculateSimilarity(keywords, docKeywords);
        return { doc, data, similarity };
      })
      .filter(item => item.similarity > 0.3)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, 3);

    if (similar.length === 0) {
      return '- No similar projects found';
    }

    return similar.map(item => `
- Similar project (${(item.similarity * 100).toFixed(0)}% match):
  Spaces: ${item.data.measurements?.parkingSpaces?.total || 'N/A'}
  Linear footage: ${item.data.measurements?.linearFootage?.value || 'N/A'} ft
  Final cost: $${item.data.actualCost?.toFixed(2) || item.data.estimate?.total?.toFixed(2)}
  Cost per space: $${item.data.actualCost ? (item.data.actualCost / item.data.measurements?.parkingSpaces?.total).toFixed(2) : 'N/A'}
  Duration: ${item.data.completionDays || 'N/A'} days
`).join('\n');
  }

  private extractKeywords(text: string): string[] {
    const keywords = text.toLowerCase()
      .match(/\b(retail|office|warehouse|school|hospital|church|apartment|shopping|medical|industrial|parking|striping|restriping|lot|garage)\b/g);
    return [...new Set(keywords || [])];
  }

  private calculateSimilarity(keywords1: string[], keywords2: string[]): number {
    const intersection = keywords1.filter(k => keywords2.includes(k)).length;
    const union = new Set([...keywords1, ...keywords2]).size;
    return union > 0 ? intersection / union : 0;
  }

  /**
   * Get recent feedback and lessons learned
   */
  private async getRecentFeedback(): Promise<string> {
    const oneMonthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    
    const snapshot = await db.collection('feedback')
      .where('timestamp', '>=', oneMonthAgo)
      .orderBy('timestamp', 'desc')
      .limit(10)
      .get();

    if (snapshot.empty) {
      return '- No recent feedback';
    }

    const feedback = snapshot.docs.map(doc => {
      const data = doc.data();
      return `
- ${data.type} (${new Date(data.timestamp.toDate()).toLocaleDateString()}):
  Issue: ${data.issue}
  Resolution: ${data.resolution}
  Lesson: ${data.lesson}`;
    });

    return feedback.join('\n');
  }

  /**
   * Identify successful patterns
   */
  private async getSuccessPatterns(): Promise<string> {
    // Get high-performing estimates
    const snapshot = await db.collection('estimates')
      .where('status', '==', 'won')
      .where('clientSatisfaction', '>=', 4)
      .orderBy('clientSatisfaction', 'desc')
      .limit(20)
      .get();

    if (snapshot.empty) {
      return '- No clear success patterns identified yet';
    }

    // Analyze patterns
    const data = snapshot.docs.map(d => d.data());
    
    const avgResponseTime = data.reduce((sum, d) => sum + (d.responseTimeHours || 0), 0) / data.length;
    const avgConfidence = data.reduce((sum, d) => sum + (d.confidence || 0), 0) / data.length;
    
    return `
Patterns from successful estimates (won + satisfied clients):
- Average response time: ${avgResponseTime.toFixed(1)} hours (${avgResponseTime < 24 ? 'FAST' : 'SLOW'})
- Average confidence: ${(avgConfidence * 100).toFixed(0)}%
- Common traits:
  ${data.filter(d => d.detailedBreakdown).length > data.length * 0.7 ? '✓ Detailed cost breakdowns win more often' : ''}
  ${data.filter(d => d.followUpOffer).length > data.length * 0.6 ? '✓ Offering follow-up calls increases conversion' : ''}
  ${data.filter(d => d.warrantyMentioned).length > data.length * 0.8 ? '✓ Mentioning warranty/guarantee helps' : ''}
`;
  }

  /**
   * Get dynamic pricing adjustments
   */
  private async getPricingAdjustments(): Promise<string> {
    const snapshot = await db.collection('pricing_adjustments')
      .where('active', '==', true)
      .get();

    if (snapshot.empty) {
      return '- No pricing adjustments currently active';
    }

    return snapshot.docs.map(doc => {
      const data = doc.data();
      return `
- ${data.name}: ${data.adjustment > 0 ? '+' : ''}${(data.adjustment * 100).toFixed(0)}%
  Reason: ${data.reason}
  Applies to: ${data.conditions}`;
    }).join('\n');
  }
}

// ===================================================================
// FEEDBACK & LEARNING SYSTEM
// ===================================================================

export class FeedbackSystem {
  /**
   * Record user feedback on estimate
   */
  async recordFeedback(feedback: {
    estimateId: string;
    userId: string;
    type: 'correction' | 'approval' | 'rejection' | 'improvement';
    category?: 'measurement' | 'pricing' | 'response_quality' | 'other';
    details: string;
    correctedValues?: any;
    satisfaction?: number; // 1-5
  }): Promise<void> {
    const feedbackDoc = await db.collection('feedback').add({
      ...feedback,
      timestamp: new Date(),
      processed: false
    });

    logger.info('Feedback recorded', { 
      feedbackId: feedbackDoc.id,
      type: feedback.type,
      category: feedback.category
    });

    // Immediate learning for corrections
    if (feedback.type === 'correction' && feedback.correctedValues) {
      await this.learnFromCorrection(feedback);
    }

    // Analyze patterns if enough feedback accumulated
    await this.triggerPatternAnalysis();
  }

  /**
   * Learn from user corrections
   */
  private async learnFromCorrection(feedback: any): Promise<void> {
    const estimate = await db.collection('estimates').doc(feedback.estimateId).get();
    const estimateData = estimate.data();

    // Store learning
    await db.collection('agent_learnings').add({
      type: 'correction',
      category: feedback.category,
      original: estimateData,
      corrected: feedback.correctedValues,
      pattern: this.extractPattern(estimateData, feedback.correctedValues),
      timestamp: new Date()
    });

    logger.info('Learning recorded from correction', {
      category: feedback.category,
      estimateId: feedback.estimateId
    });
  }

  private extractPattern(original: any, corrected: any): any {
    // Identify what changed and why
    const pattern: any = { observations: [] };

    // Measurement corrections
    if (corrected.measurements) {
      Object.keys(corrected.measurements).forEach(key => {
        const orig = original.measurements?.[key];
        const corr = corrected.measurements[key];
        
        if (orig && corr && orig !== corr) {
          const variance = ((corr - orig) / orig) * 100;
          pattern.observations.push({
            field: key,
            originalValue: orig,
            correctedValue: corr,
            variance: variance.toFixed(1) + '%',
            lesson: this.generateLesson(key, variance)
          });
        }
      });
    }

    return pattern;
  }

  private generateLesson(field: string, variance: number): string {
    if (Math.abs(variance) < 10) {
      return `Minor ${variance > 0 ? 'underestimate' : 'overestimate'} in ${field}. Within acceptable range.`;
    }
    
    if (variance > 20) {
      return `Significant underestimate in ${field}. Consider: 1) Better image analysis, 2) Account for scale, 3) Check for hidden areas.`;
    }
    
    if (variance < -20) {
      return `Significant overestimate in ${field}. Consider: 1) Double-count detection, 2) Include only necessary items, 3) Verify measurements.`;
    }

    return `Moderate variance in ${field}. Review analysis method.`;
  }

  /**
   * Analyze patterns when sufficient feedback exists
   */
  private async triggerPatternAnalysis(): Promise<void> {
    const unprocessedCount = await db.collection('feedback')
      .where('processed', '==', false)
      .count()
      .get();

    if (unprocessedCount.data().count >= 10) {
      logger.info('Triggering pattern analysis', { feedbackCount: unprocessedCount.data().count });
      await this.analyzeAndUpdatePrompts();
    }
  }

  /**
   * Use AI to analyze feedback and update agent prompts
   */
  private async analyzeAndUpdatePrompts(): Promise<void> {
    // Get unprocessed feedback
    const snapshot = await db.collection('feedback')
      .where('processed', '==', false)
      .limit(50)
      .get();

    const feedbackData = snapshot.docs.map(doc => doc.data());

    // Use Gemini to analyze patterns
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash-exp' });
    
    const analysisPrompt = `
Analyze this feedback from parking lot estimate processing:

${JSON.stringify(feedbackData, null, 2)}

Identify:
1. Common error patterns
2. Systematic biases (underestimating/overestimating)
3. Categories with most issues
4. Specific improvements needed

Provide:
- Summary of key issues
- Specific prompt improvements for the AI agent
- New validation rules to add
- Training examples to include

Format as JSON.
`;

    const result = await model.generateContent(analysisPrompt);
    const analysis = JSON.parse(result.response.text());

    // Store analysis
    await db.collection('learning_insights').add({
      analysis,
      feedbackCount: feedbackData.length,
      timestamp: new Date()
    });

    // Update agent instructions
    await this.updateAgentInstructions(analysis);

    // Mark feedback as processed
    const batch = db.batch();
    snapshot.docs.forEach(doc => {
      batch.update(doc.ref, { processed: true, processedAt: new Date() });
    });
    await batch.commit();

    logger.info('Pattern analysis complete and prompts updated', {
      feedbackProcessed: feedbackData.length
    });
  }

  private async updateAgentInstructions(analysis: any): Promise<void> {
    const currentInstructions = await db.collection('config').doc('agent_instructions').get();
    const current = currentInstructions.data() || {};

    const updated = {
      ...current,
      learnings: analysis.keyIssues || [],
      improvements: analysis.promptImprovements || [],
      validationRules: [...(current.validationRules || []), ...(analysis.newValidationRules || [])],
      examples: [...(current.examples || []), ...(analysis.trainingExamples || [])],
      lastUpdated: new Date(),
      version: (current.version || 0) + 1
    };

    await db.collection('config').doc('agent_instructions').set(updated);
  }
}

// ===================================================================
// PERFORMANCE TRACKING
// ===================================================================

export class PerformanceTracker {
  /**
   * Track estimate performance metrics
   */
  async trackEstimatePerformance(estimate: any, outcome: {
    won?: boolean;
    actualCost?: number;
    completionDays?: number;
    clientSatisfaction?: number;
    issuesEncountered?: string[];
  }): Promise<void> {
    await db.collection('estimates').doc(estimate.id).update({
      ...outcome,
      performanceTrackedAt: new Date()
    });

    // Calculate accuracy score
    if (outcome.actualCost) {
      const variance = Math.abs((outcome.actualCost - estimate.estimate.total) / estimate.estimate.total);
      const accuracyScore = Math.max(0, 100 - (variance * 100));

      await db.collection('performance_metrics').add({
        estimateId: estimate.id,
        accuracyScore,
        variance,
        measurementAccuracy: this.calculateMeasurementAccuracy(estimate, outcome),
        responseQuality: estimate.confidence,
        timestamp: new Date()
      });

      logger.info('Performance tracked', {
        estimateId: estimate.id,
        accuracyScore: accuracyScore.toFixed(1),
        won: outcome.won
      });
    }
  }

  private calculateMeasurementAccuracy(estimate: any, outcome: any): number {
    // Compare estimated vs actual measurements if available
    if (!outcome.actualMeasurements) return null;

    const fields = ['linearFootage', 'squareFootage', 'parkingSpaces'];
    let totalVariance = 0;
    let fieldCount = 0;

    fields.forEach(field => {
      const estimated = estimate.measurements?.[field]?.value;
      const actual = outcome.actualMeasurements?.[field];
      
      if (estimated && actual) {
        totalVariance += Math.abs((actual - estimated) / estimated);
        fieldCount++;
      }
    });

    return fieldCount > 0 ? Math.max(0, 100 - ((totalVariance / fieldCount) * 100)) : null;
  }

  /**
   * Get agent performance dashboard
   */
  async getPerformanceDashboard(days: number = 30): Promise<any> {
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const metricsSnapshot = await db.collection('performance_metrics')
      .where('timestamp', '>=', startDate)
      .get();

    const metrics = metricsSnapshot.docs.map(d => d.data());

    const avgAccuracy = metrics.reduce((sum, m) => sum + m.accuracyScore, 0) / metrics.length || 0;
    const avgMeasurementAccuracy = metrics
      .filter(m => m.measurementAccuracy)
      .reduce((sum, m) => sum + m.measurementAccuracy, 0) / metrics.filter(m => m.measurementAccuracy).length || 0;

    // Get estimates
    const estimatesSnapshot = await db.collection('estimates')
      .where('createdAt', '>=', startDate)
      .get();

    const estimates = estimatesSnapshot.docs.map(d => d.data());
    const totalEstimates = estimates.length;
    const autoSent = estimates.filter(e => e.status === 'auto_sent').length;
    const won = estimates.filter(e => e.status === 'won').length;
    const avgSatisfaction = estimates
      .filter(e => e.clientSatisfaction)
      .reduce((sum, e) => sum + e.clientSatisfaction, 0) / estimates.filter(e => e.clientSatisfaction).length || 0;

    return {
      period: `Last ${days} days`,
      overview: {
        totalEstimates,
        autoSentRate: ((autoSent / totalEstimates) * 100).toFixed(1) + '%',
        winRate: ((won / totalEstimates) * 100).toFixed(1) + '%',
        avgSatisfaction: avgSatisfaction.toFixed(1) + '/5'
      },
      accuracy: {
        avgCostAccuracy: avgAccuracy.toFixed(1) + '%',
        avgMeasurementAccuracy: avgMeasurementAccuracy.toFixed(1) + '%',
        trend: this.calculateTrend(metrics)
      },
      improvements: await this.identifyImprovements(metrics, estimates)
    };
  }

  private calculateTrend(metrics: any[]): string {
    if (metrics.length < 10) return 'Insufficient data';

    const recent = metrics.slice(-10);
    const older = metrics.slice(0, 10);

    const recentAvg = recent.reduce((sum, m) => sum + m.accuracyScore, 0) / recent.length;
    const olderAvg = older.reduce((sum, m) => sum + m.accuracyScore, 0) / older.length;

    const change = ((recentAvg - olderAvg) / olderAvg) * 100;

    if (Math.abs(change) < 2) return 'Stable';
    return change > 0 ? `Improving (+${change.toFixed(1)}%)` : `Declining (${change.toFixed(1)}%)`;
  }

  private async identifyImprovements(metrics: any[], estimates: any[]): Promise<string[]> {
    const improvements = [];

    const lowAccuracy = metrics.filter(m => m.accuracyScore < 85).length / metrics.length;
    if (lowAccuracy > 0.2) {
      improvements.push(`${(lowAccuracy * 100).toFixed(0)}% of estimates have 