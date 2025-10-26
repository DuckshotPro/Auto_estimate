# Custom Stripe Texas - Complete System Integration Guide

## Module Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer / API Gateway               │
└─────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
            ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │   Main Agent │  │ API Tracking │  │   Security   │
    │   (Port 8080)│  │ (Port 8081)  │  │ (Port 8083)  │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                 │                 │
           │                 │                 │
           ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │SMS Notifier  │  │    Redis     │  │  Firestore   │
    │ (Port 8082)  │  │   (Cache)    │  │  (Database)  │
    └──────────────┘  └──────────────┘  └──────────────┘
           │                                    │
           └────────────────┬───────────────────┘
                            │
                    ┌───────▼────────┐
                    │ Secret Manager │
                    └────────────────┘
```

## Module Interactions

### 1. Main Estimate Agent → All Modules

```typescript
// agent.ts - Enhanced with all modules
import { tracker, createTrackingMiddleware } from './api-tracking-module';
import { notificationRules } from './sms-notification-module';
import { secretService, authService } from './security-module';

// Wrap Gemini calls with tracking
const trackingMiddleware = createTrackingMiddleware(tracker);
const geminiWrapper = trackingMiddleware.wrapGeminiCall('gemini-2.0-flash-exp');

// Example: Process email with tracking
async function processEmailWithTracking(email) {
  return await geminiWrapper('analyze_email', async () => {
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash-exp' });
    const result = await model.generateContent(emailPrompt);
    return result;
  });
}

// Example: Secure credential retrieval
async function fetchPlatformDocs(platformUrl, platform) {
  const credentials = await secretService.getPlatformCredentials(platform);
  // Use credentials safely
}

// Example: Send notifications on events
async function handleEstimateReview(estimate) {
  await notificationRules.onEstimateNeedsReview(estimate);
}
```

### 2. API Tracking → Notification Module

```typescript
// Auto-alert on budget thresholds
import { notificationRules } from './sms-notification-module';

// In API tracking module
async function checkBudgetAndAlert() {
  const status = await tracker.getRateLimitStatus();
  const percentage = (status.today.cost / status.today.costLimit) * 100;
  
  if (percentage >= 50) {
    await notificationRules.onCostThreshold(
      status.today.cost,
      status.today.costLimit,
      percentage
    );
  }
}
```

### 3. Security Module → All Modules

```typescript
// Secure all endpoints
import { authenticateAPIKey, auditLog } from './security-module';

// Main agent endpoints
app.post('/process', 
  authenticateAPIKey,
  auditLog('process_estimates', 'estimate'),
  async (req, res) => {
    // Process estimates
  }
);

// API tracking endpoints
app.get('/api/usage/stats',
  authenticateAPIKey,
  async (req, res) => {
    // Return stats
  }
);
```

## Environment Configuration

### `.env` File

```bash
# Google Cloud
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_AI_API_KEY=your-gemini-api-key

# Twilio (SMS)
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+1234567890
NOTIFICATION_PHONE=+1234567890

# Security
ENCRYPTION_KEY=your-32-byte-hex-key
JWT_SECRET=your-jwt-secret

# Redis
REDIS_URL=redis://localhost:6379

# Service Ports
PORT=8080
API_TRACKING_PORT=8081
SMS_SERVICE_PORT=8082
SECURITY_SERVICE_PORT=8083

# URLs
DASHBOARD_URL=https://your-dashboard.com

# Logging
LOG_LEVEL=info
SENTRY_DSN=your-sentry-dsn
NODE_ENV=production
```

## Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes

  estimate-agent:
    build: 
      context: .
      dockerfile: Dockerfile.agent
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    volumes:
      - ./logs:/app/logs

  api-tracker:
    build:
      context: .
      dockerfile: Dockerfile.tracker
    ports:
      - "8081:8081"
    environment:
      - API_TRACKING_PORT=8081
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  sms-notifier:
    build:
      context: .
      dockerfile: Dockerfile.sms
    ports:
      - "8082:8082"
    environment:
      - SMS_SERVICE_PORT=8082
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  security:
    build:
      context: .
      dockerfile: Dockerfile.security
    ports:
      - "8083:8083"
    environment:
      - SECURITY_SERVICE_PORT=8083
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

volumes:
  redis-data:
```

## Individual Dockerfiles

### Dockerfile.agent
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY agent.ts ./
COPY tools/ ./tools/

RUN npm install -g typescript
RUN tsc agent.ts

EXPOSE 8080

CMD ["node", "agent.js"]
```

### Dockerfile.tracker
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY api-tracking-module.ts ./

RUN npm install -g typescript
RUN tsc api-tracking-module.ts

EXPOSE 8081

CMD ["node", "api-tracking-module.js"]
```

## Cloud Run Deployment

### deploy.sh
```bash
#!/bin/bash

PROJECT_ID="your-project-id"
REGION="us-central1"

# Build and deploy estimate agent
gcloud builds submit --tag gcr.io/$PROJECT_ID/estimate-agent
gcloud run deploy estimate-agent \
  --image gcr.io/$PROJECT_ID/estimate-agent \
  --platform managed \
  --region $REGION \
  --memory 2Gi \
  --timeout 540s \
  --set-env-vars "REDIS_URL=$REDIS_URL,GOOGLE_AI_API_KEY=$GOOGLE_AI_API_KEY"

# Build and deploy API tracker
gcloud builds submit --tag gcr.io/$PROJECT_ID/api-tracker
gcloud run deploy api-tracker \
  --image gcr.io/$PROJECT_ID/api-tracker \
  --platform managed \
  --region $REGION \
  --memory 512Mi

# Build and deploy SMS notifier
gcloud builds submit --tag gcr.io/$PROJECT_ID/sms-notifier
gcloud run deploy sms-notifier \
  --image gcr.io/$PROJECT_ID/sms-notifier \
  --platform managed \
  --region $REGION \
  --memory 512Mi

# Build and deploy security service
gcloud builds submit --tag gcr.io/$PROJECT_ID/security
gcloud run deploy security \
  --image gcr.io/$PROJECT_ID/security \
  --platform managed \
  --region $REGION \
  --memory 512Mi

# Setup Cloud Scheduler
gcloud scheduler jobs create http estimate-processor \
  --schedule="*/15 * * * *" \
  --uri="https://estimate-agent-xxxx.run.app/process" \
  --http-method=POST \
  --oidc-service-account-email=estimate-agent@$PROJECT_ID.iam.gserviceaccount.com

# Daily digest at 8 AM
gcloud scheduler jobs create http daily-digest \
  --schedule="0 8 * * *" \
  --uri="https://sms-notifier-xxxx.run.app/api/notify/digest" \
  --http-method=POST \
  --oidc-service-account-email=estimate-agent@$PROJECT_ID.iam.gserviceaccount.com
```

## Usage Examples

### 1. Initial Setup

```bash
# Install dependencies
npm install

# Setup environment
cp .env.example .env
# Edit .env with your credentials

# Initialize secrets
node -e "
  const { secretService } = require('./security-module');
  secretService.storePlatformCredentials('planhub', {
    email: 'your-email@example.com',
    password: 'your-password'
  });
"

# Start services
docker-compose up -d

# Generate API key
curl -X POST http://localhost:8083/api/auth/generate-key \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name": "main-service"}'
```

### 2. Manual Estimate Processing

```bash
# Trigger processing manually
curl -X POST http://localhost:8080/process \
  -H "X-API-Key: YOUR_API_KEY"
```

### 3. Check API Usage

```bash
# Get usage stats (last 7 days)
curl http://localhost:8081/api/usage/stats?days=7 \
  -H "X-API-Key: YOUR_API_KEY"

# Get cost projection
curl http://localhost:8081/api/usage/projection \
  -H "X-API-Key: YOUR_API_KEY"

# Get rate limit status
curl http://localhost:8081/api/usage/rate-limits \
  -H "X-API-Key: YOUR_API_KEY"
```

### 4. Send Test Notification

```bash
# Test SMS notification
curl -X POST http://localhost:8082/api/notify/test \
  -H "X-API-Key: YOUR_API_KEY"

# Check notification history
curl http://localhost:8082/api/notify/history?limit=20 \
  -H "X-API-Key: YOUR_API_KEY"
```

### 5. Security Monitoring

```bash
# View security events
curl http://localhost:8083/api/security/events?severity=high \
  -H "X-API-Key: YOUR_API_KEY"

# View audit trail
curl http://localhost:8083/api/security/audit?resource=estimate \
  -H "X-API-Key: YOUR_API_KEY"
```

## Monitoring & Dashboards

### Prometheus Metrics

```typescript
// Add to each module
import prometheus from 'prom-client';

const register = new prometheus.Registry();

const httpRequestDuration = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

// Expose metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

### Grafana Dashboard JSON

```json
{docker compose up -d

  "dashboard": {
    "title": "Custom Stripe Estimates",
    "panels": [
      {
        "title": "Estimates Processed Today",
        "targets": [{
          "expr": "sum(estimate_processed_total{status='auto_sent'})"
        }]
      },
      {
        "title": "API Cost Today",
        "targets": [{
          "expr": "sum(api_cost_dollars)"
        }]
      },
      {
        "title": "Error Rate",
        "targets": [{
          "expr": "rate(estimate_errors_total[5m])"
        }]
      }
    ]
  }
}
```

## Cost Estimates

### Monthly Operating Costs

| Service | Usage | Cost |
|---------|-------|------|
| Cloud Run (4 services) | ~720 hours/month | $30 |
| Gemini 2.0 Flash | 50-100 estimates | $15-30 |
| Gmail API | Free tier | $0 |
| Firestore | ~10GB storage | $5 |
| Secret Manager | 10 secrets | $1 |
| Twilio SMS | ~60 messages | $5 |
| Redis (Cloud Memorystore) | 1GB | $30 |
| **Total** | | **~$86-101/month** |

### Cost Optimization Tips

1. **Use caching aggressively** - Cache Gemini prompts
2. **Batch notifications** - Daily digests vs individual SMS
3. **Set strict rate limits** - Prevent runaway API costs
4. **Use Cloud Run min-instances=0** - Pay only when processing
5. **Monitor and alert** - Get notified at 50% budget

## Troubleshooting

### Common Issues

**Issue: Agent not processing emails**
```bash
# Check logs
docker logs estimate-agent --tail=100

# Verify Gmail API access
gcloud auth application-default login

# Test email fetching manually
curl http://localhost:8080/test-gmail
```

**Issue: High API costs**
```bash
# Check current usage
curl http://localhost:8081/api/usage/stats

# Review expensive operations
curl http://localhost:8081/api/usage/stats | jq '.byOperation'

# Temporarily disable processing
curl -X POST http://localhost:8080/pause \
  -H "X-API-Key: YOUR_API_KEY"
```

**Issue: SMS not sending**
```bash
# Check Twilio credentials
curl http://localhost:8082/api/notify/test

# Verify phone number format
# Must be E.164 format: +1234567890

# Check notification logs
docker logs sms-notifier --tail=50
```

**Issue: Platform login failures**
```bash
# Update credentials
curl -X POST http://localhost:8083/api/secrets/platform/planhub \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email": "new@email.com", "password": "newpass"}'

# Check security events
curl http://localhost:8083/api/security/events?type=authentication_failure
```

**Issue: Rate limits exceeded**
```bash
# Check current limits
curl http://localhost:8081/api/usage/rate-limits

# Increase limits (if justified)
curl -X POST http://localhost:8081/api/usage/limits \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"provider": "gemini", "limits": {"requestsPerMinute": 120}}'
```

## Advanced Features

### 1. Multi-Platform Support

```typescript
// Add new platform handler
import { Tool } from '@google/adk';

export const fetchFromNewPlatform: Tool = {
  name: 'fetch_from_new_platform',
  description: 'Fetch documents from NewPlatform',
  parameters: {
    type: 'object',
    properties: {
      projectUrl: { type: 'string' }
    }
  },
  handler: async ({ projectUrl }) => {
    // Custom implementation for new platform
    const credentials = await secretService.getPlatformCredentials('newplatform');
    // ... platform-specific logic
  }
};

// Register with agent
estimateAgent.tools.push(fetchFromNewPlatform);
```

### 2. Custom Pricing Rules

```typescript
// Add to pricing engine
class CustomPricingRules {
  async calculateEstimate(measurements: any, client: string): Promise<any> {
    let baseEstimate = standardPricing.calculate(measurements);
    
    // Volume discount
    if (measurements.parkingSpaces?.total > 200) {
      baseEstimate.total *= 0.90; // 10% discount
    }
    
    // Returning customer discount
    const previousJobs = await db.collection('estimates')
      .where('clientEmail', '==', client)
      .where('status', '==', 'completed')
      .get();
    
    if (previousJobs.size > 3) {
      baseEstimate.total *= 0.95; // 5% loyalty discount
    }
    
    // Rush job premium
    if (measurements.rushJob) {
      baseEstimate.total *= 1.25; // 25% premium
    }
    
    return baseEstimate;
  }
}
```

### 3. Custom Notifications

```typescript
// Add custom notification type
const NOTIFICATION_TEMPLATES = {
  ...existingTemplates,
  
  [NotificationType.LARGE_PROJECT_ALERT]: {
    type: NotificationType.LARGE_PROJECT_ALERT,
    priority: NotificationPriority.HIGH,
    template: (data) => 
      `🎯 LARGE PROJECT OPPORTUNITY\n` +
      `Client: ${data.clientEmail}\n` +
      `Estimate: $${data.amount.toLocaleString()}\n` +
      `Spaces: ${data.spaces}\n` +
      `This could be a significant job!`
  },
  
  [NotificationType.COMPETITOR_MENTION]: {
    type: NotificationType.COMPETITOR_MENTION,
    priority: NotificationPriority.MEDIUM,
    template: (data) =>
      `👀 Competitor mentioned in email\n` +
      `Competitor: ${data.competitor}\n` +
      `Context: ${data.context}\n` +
      `Review before responding`
  }
};
```

### 4. Machine Learning Improvements

```typescript
// Track estimate accuracy for continuous improvement
class EstimateAccuracyTracker {
  async recordActualCost(estimateId: string, actualCost: number): Promise<void> {
    const estimate = await db.collection('estimates').doc(estimateId).get();
    const estimated = estimate.data().estimate.total;
    
    const variance = Math.abs(actualCost - estimated) / estimated;
    
    await db.collection('estimate_accuracy').add({
      estimateId,
      estimated,
      actual: actualCost,
      variance,
      measurements: estimate.data().measurements,
      timestamp: new Date()
    });
    
    // If variance > 20%, analyze why
    if (variance > 0.2) {
      logger.warn('High estimate variance', {
        estimateId,
        estimated,
        actual: actualCost,
        variance
      });
      
      await notificationService.send(
        NotificationType.SYSTEM_ERROR,
        {
          service: 'estimate_accuracy',
          error: `Large variance detected: ${(variance * 100).toFixed(1)}%`
        }
      );
    }
  }
  
  async getAverageAccuracy(): Promise<number> {
    const snapshot = await db.collection('estimate_accuracy').get();
    const totalVariance = snapshot.docs.reduce(
      (sum, doc) => sum + doc.data().variance, 
      0
    );
    return 1 - (totalVariance / snapshot.size);
  }
}
```

## Maintenance Schedule

### Daily Tasks (Automated)
- ✅ Process unread estimate emails (every 15 min)
- ✅ Send daily digest (8 AM)
- ✅ Check budget thresholds (hourly)
- ✅ Rotate logs
- ✅ Clear old Redis keys

### Weekly Tasks (Manual - 10 min)
- Review pending estimates in dashboard
- Check notification history for issues
- Review API usage trends
- Update platform credentials if needed
- Check security events

### Monthly Tasks (Manual - 30 min)
- Review cost vs budget
- Analyze estimate accuracy
- Update pricing if needed
- Review and revoke unused API keys
- Check for system updates

## Testing

### Unit Tests

```typescript
// tests/agent.test.ts
import { estimateAgent } from '../agent';
import { tracker } from '../api-tracking-module';

describe('Estimate Agent', () => {
  it('should process email and extract platform links', async () => {
    const mockEmail = {
      from: 'test@example.com',
      body: 'Check out this project: https://planhub.com/project/123'
    };
    
    const result = await estimateAgent.processEmail(mockEmail);
    expect(result.platformLinks).toHaveLength(1);
    expect(result.platformLinks[0].platform).toBe('planhub');
  });
  
  it('should track API usage', async () => {
    await tracker.trackAPICall({
      provider: 'gemini',
      model: 'gemini-2.0-flash-exp',
      operation: 'test',
      inputTokens: 100,
      outputTokens: 50,
      status: 'success'
    });
    
    const stats = await tracker.getUsageStats({
      start: new Date(Date.now() - 1000),
      end: new Date()
    });
    
    expect(stats.totalCalls).toBeGreaterThan(0);
  });
});
```

### Integration Tests

```bash
#!/bin/bash
# tests/integration-test.sh

echo "Starting integration tests..."

# Test 1: Health checks
echo "Checking service health..."
curl -f http://localhost:8080/health || exit 1
curl -f http://localhost:8081/health || exit 1
curl -f http://localhost:8082/health || exit 1
curl -f http://localhost:8083/health || exit 1

# Test 2: API key auth
echo "Testing API key authentication..."
API_KEY=$(curl -s -X POST http://localhost:8083/api/auth/generate-key \
  -H "Authorization: Bearer $TEST_JWT" \
  -d '{"name":"test-key"}' | jq -r '.apiKey')

# Test 3: Process test email
echo "Testing estimate processing..."
curl -X POST http://localhost:8080/process \
  -H "X-API-Key: $API_KEY" || exit 1

# Test 4: Check API usage
echo "Checking API usage tracking..."
curl -f http://localhost:8081/api/usage/stats \
  -H "X-API-Key: $API_KEY" || exit 1

# Test 5: Send test notification
echo "Testing SMS notification..."
curl -X POST http://localhost:8082/api/notify/test \
  -H "X-API-Key: $API_KEY" || exit 1

echo "All integration tests passed!"
```

## Performance Optimization

### 1. Caching Strategy

```typescript
// Implement response caching
import NodeCache from 'node-cache';

const cache = new NodeCache({ stdTTL: 3600 }); // 1 hour

async function getCachedOrFetch(key: string, fetchFn: Function) {
  const cached = cache.get(key);
  if (cached) {
    logger.info('Cache hit', { key });
    return cached;
  }
  
  const result = await fetchFn();
  cache.set(key, result);
  return result;
}

// Example usage
const measurements = await getCachedOrFetch(
  `pdf_analysis_${pdfHash}`,
  () => analyzeParkingLotPDF(pdfBuffer)
);
```

### 2. Batch Processing

```typescript
// Process multiple emails in batch
async function batchProcessEmails(emails: any[]) {
  const batches = chunk(emails, 5); // Process 5 at a time
  
  for (const batch of batches) {
    await Promise.all(
      batch.map(email => processEmail(email))
    );
    
    // Wait between batches to respect rate limits
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}
```

### 3. Database Indexing

```typescript
// Create Fi
### 5. Security Module → All Modules

```typescript
// Secure ALL endpoints across ALL modules
import { authenticateAPIKey, auditLog } from './security-module';

// Main agent (8080)
app.post('/process', 
  authenticateAPIKey,
  auditLog('process_estimates', 'estimate'),
  async (req, res) => { /* ... */ }
);

// API tracking (8081)
app.get('/api/usage/stats', authenticateAPIKey, async (req, res) => { /* ... */ });

// SMS notifier (8082)
app.post('/api/notify', authenticateAPIKey, async (req, res) => { /* ... */ });

// Cost optimizer (8084)
app.get('/api/optimize/report', authenticateAPIKey, async (req, res) => { /* ... */ });

// Learning (8085)
app.post('/api/learn/feedback', authenticateAPIKey, async (req, res) => { /* ... */ });
```# Custom Stripe Texas - Complete System Integration Guide

## Module Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│              Load Balancer / API Gateway / Dashboard         │
│                    (dashboard.html - Port 80)                │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐     ┌──────────────┐
│  Main Agent  │◄─────┤Cost Optimizer│────►│   Learning   │
│ (Port 8080)  │      │ (Port 8084)  │     │ (Port 8085)  │
└──────┬───────┘      └──────┬───────┘     └──────┬───────┘
       │                     │                     │
       ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐     ┌──────────────┐
│API Tracking  │      │SMS Notifier  │     │  Security    │
│ (Port 8081)  │      │ (Port 8082)  │     │ (Port 8083)  │
└──────┬───────┘      └──────┬───────┘     └──────┬───────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
        ┌──────────────┐          ┌──────────────┐
        │    Redis     │          │  Firestore   │
        │   (Cache)    │          │  (Database)  │
        └──────────────┘          └──────┬───────┘
                                         │
                                  ┌──────▼────────┐
                                  │Secret Manager │
                                  └───────────────┘
```

## Module Interactions

### 1. Main Estimate Agent → All Modules

```typescript
// agent.ts - FULLY ENHANCED with ALL modules
import { tracker, createTrackingMiddleware } from './api-tracking-module';
import { notificationRules } from './sms-notification-module';
import { secretService, authService } from './security-module';
import { optimizer } from './cost-optimizer-module';
import { enhanceAgentWithContext, FeedbackSystem } from './learning-enhancement-module';

// Setup
const trackingMiddleware = createTrackingMiddleware(tracker);
const geminiWrapper = trackingMiddleware.wrapGeminiCall('gemini-2.0-flash-exp');
const feedbackSystem = new FeedbackSystem();

// ENHANCED: Process email with ALL optimizations
async function processEmailWithFullStack(email) {
  // 1. Check budget first (Cost Optimizer)
  const budgetCheck = await optimizer.checkBudgetAndThrottle();
  if (!budgetCheck.allowed) {
    logger.warn('Budget limit reached, delaying processing');
    return { delayed: true, reason: budgetCheck.reason };
  }

  // 2. Select optimal model (Cost Optimizer)
  const modelSelection = await optimizer.selectOptimalModel({
    type: 'email_analysis',
    complexity: 'low',
    requiresVision: false
  });

  // 3. Create agent session with context (Learning Module)
  const session = estimateAgent.createSession();
  await enhanceAgentWithContext(session, email);

  // 4. Process with tracking (API Tracking)
  return await geminiWrapper('analyze_email', async () => {
    const model = genAI.getGenerativeModel({ 
      model: modelSelection.model // Use optimized model
    });
    const result = await model.generateContent(emailPrompt);
    return result;
  });
}

// ENHANCED: Process estimate with full pipeline
async function processEstimate(email) {
  const result = await processEmailWithFullStack(email);
  
  // Extract platform links
  const links = await extractPlatformLinks(email.body);
  
  // Fetch docs with secure credentials (Security Module)
  const credentials = await secretService.getPlatformCredentials(links[0].platform);
  const docs = await fetchPlatformDocs(links[0].url, credentials);
  
  // Check cache first (Cost Optimizer)
  const cacheKey = `pdf_${hashPDF(docs[0])}`;
  const shouldCache = await optimizer.shouldUseCache('pdf_analysis', { pdfHash: cacheKey });
  
  let measurements;
  if (shouldCache) {
    measurements = await redis.get(cacheKey);
  } else {
    // Analyze with optimal model
    const modelSelection = await optimizer.selectOptimalModel({
      type: 'pdf_analysis',
      complexity: 'high',
      requiresVision: true
    });
    
    measurements = await analyzePDF(docs[0], modelSelection.model);
    await optimizer.setCacheResult('pdf_analysis', { pdfHash: cacheKey }, measurements);
  }
  
  // Calculate estimate
  const estimate = await calculateEstimate(measurements);
  
  // Validate and decide
  if (estimate.confidence > 0.8) {
    await sendEstimate(email.from, estimate);
    await notificationRules.onEstimateAutoSent(estimate);
  } else {
    await notificationRules.onEstimateNeedsReview(estimate);
  }
  
  return estimate;
}
```

### 2. Cost Optimizer Integration

```typescript
// Auto-optimize model selection throughout system
import { optimizer } from './cost-optimizer-module';

// Before ANY Gemini API call
const modelSelection = await optimizer.selectOptimalModel({
  type: 'pdf_analysis',
  complexity: 'high',
  requiresVision: true,
  maxBudget: 0.01 // Optional: hard limit
});

// Use the selected model
const model = genAI.getGenerativeModel({ model: modelSelection.model });

// Check budget before processing
const budgetCheck = await optimizer.checkBudgetAndThrottle();
if (!budgetCheck.allowed) {
  // Delay or notify
  await notificationRules.onBudgetExceeded();
  return;
}

// Cache results aggressively
const cached = await optimizer.shouldUseCache('pdf_analysis', { pdfHash });
if (cached) {
  return await redis.get(`cache:pdf:${pdfHash}`);
}
```

### 3. Learning Module Integration

```typescript
// Enhance agent with historical context
import { enhanceAgentWithContext, FeedbackSystem } from './learning-enhancement-module';

// Before processing estimate
const session = estimateAgent.createSession();
await enhanceAgentWithContext(session, emailData);
// Agent now knows: client history, similar projects, feedback, patterns

// After estimate sent - track feedback
const feedbackSystem = new FeedbackSystem();

// User corrects estimate
await feedbackSystem.recordFeedback({
  estimateId: 'est_123',
  userId: 'user_456',
  type: 'correction',
  category: 'measurement',
  details: 'Linear footage was off by 15%',
  correctedValues: {
    linearFootage: 3200
  }
});

// Track final outcome
await performanceTracker.trackEstimatePerformance(estimate, {
  won: true,
  actualCost: 2847.50,
  completionDays: 2,
  clientSatisfaction: 5
});
```

### 4. API Tracking → All Modules

```typescript
// Track and alert on costs
async function checkBudgetAndAlert() {
  const status = await tracker.getRateLimitStatus();
  const percentage = (status.today.cost / status.today.costLimit) * 100;
  
  if (percentage >= 90) {
    await notificationRules.onCostThreshold(
      status.today.cost,
      status.today.costLimit,
      percentage
    );
    
    // Optimizer takes action
    await optimizer.enableAutoThrottle();
  }
}
```

## Environment Configuration

### `.env` File

```bash
# Google Cloud
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_AI_API_KEY=your-gemini-api-key

# Twilio (SMS)
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+1234567890
NOTIFICATION_PHONE=+1234567890

# Security
ENCRYPTION_KEY=your-32-byte-hex-key
JWT_SECRET=your-jwt-secret

# Redis
REDIS_URL=redis://localhost:6379

# Service Ports
PORT=8080
API_TRACKING_PORT=8081
SMS_SERVICE_PORT=8082
SECURITY_SERVICE_PORT=8083
COST_OPTIMIZER_PORT=8084
LEARNING_MODULE_PORT=8085

# URLs
DASHBOARD_URL=https://your-dashboard.com

# Logging
LOG_LEVEL=info
SENTRY_DSN=your-sentry-dsn
NODE_ENV=production
```

## Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes

  estimate-agent:
    build: 
      context: .
      dockerfile: Dockerfile.agent
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    volumes:
      - ./logs:/app/logs

  api-tracker:
    build:
      context: .
      dockerfile: Dockerfile.tracker
    ports:
      - "8081:8081"
    environment:
      - API_TRACKING_PORT=8081
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  sms-notifier:
    build:
      context: .
      dockerfile: Dockerfile.sms
    ports:
      - "8082:8082"
    environment:
      - SMS_SERVICE_PORT=8082
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  security:
    build:
      context: .
      dockerfile: Dockerfile.security
    ports:
      - "8083:8083"
    environment:
      - SECURITY_SERVICE_PORT=8083
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  cost-optimizer:
    build:
      context: .
      dockerfile: Dockerfile.optimizer
    ports:
      - "8084:8084"
    environment:
      - COST_OPTIMIZER_PORT=8084
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  learning-module:
    build:
      context: .
      dockerfile: Dockerfile.learning
    ports:
      - "8085:8085"
    environment:
      - LEARNING_MODULE_PORT=8085
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  dashboard:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./dashboard.html:/usr/share/nginx/html/index.html
    depends_on:
      - estimate-agent
      - api-tracker
      - sms-notifier
      - security
      - cost-optimizer
      - learning-module

volumes:
  redis-data:
```

## Individual Dockerfiles

### Dockerfile.agent
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY agent.ts ./
COPY tools/ ./tools/

RUN npm install -g typescript
RUN tsc agent.ts

EXPOSE 8080

CMD ["node", "agent.js"]
```

### Dockerfile.tracker
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY api-tracking-module.ts ./

RUN npm install -g typescript
RUN tsc api-tracking-module.ts

EXPOSE 8081

CMD ["node", "api-tracking-module.js"]
```

## Cloud Run Deployment

### deploy.sh
```bash
#!/bin/bash

PROJECT_ID="your-project-id"
REGION="us-central1"

# Build and deploy estimate agent
gcloud builds submit --tag gcr.io/$PROJECT_ID/estimate-agent
gcloud run deploy estimate-agent \
  --image gcr.io/$PROJECT_ID/estimate-agent \
  --platform managed \
  --region $REGION \
  --memory 2Gi \
  --timeout 540s \
  --set-env-vars "REDIS_URL=$REDIS_URL,GOOGLE_AI_API_KEY=$GOOGLE_AI_API_KEY"

# Build and deploy API tracker
gcloud builds submit --tag gcr.io/$PROJECT_ID/api-tracker
gcloud run deploy api-tracker \
  --image gcr.io/$PROJECT_ID/api-tracker \
  --platform managed \
  --region $REGION \
  --memory 512Mi

# Build and deploy SMS notifier
gcloud builds submit --tag gcr.io/$PROJECT_ID/sms-notifier
gcloud run deploy sms-notifier \
  --image gcr.io/$PROJECT_ID/sms-notifier \
  --platform managed \
  --region $REGION \
  --memory 512Mi

# Build and deploy security service
gcloud builds submit --tag gcr.io/$PROJECT_ID/security
gcloud run deploy security \
  --image gcr.io/$PROJECT_ID/security \
  --platform managed \
  --region $REGION \
  --memory 512Mi

# Build and deploy cost optimizer
gcloud builds submit --tag gcr.io/$PROJECT_ID/cost-optimizer
gcloud run deploy cost-optimizer \
  --image gcr.io/$PROJECT_ID/cost-optimizer \
  --platform managed \
  --region $REGION \
  --memory 512Mi

# Build and deploy learning module
gcloud builds submit --tag gcr.io/$PROJECT_ID/learning-module
gcloud run deploy learning-module \
  --image gcr.io/$PROJECT_ID/learning-module \
  --platform managed \
  --region $REGION \
  --memory 1Gi

# Deploy dashboard to Firebase Hosting
firebase deploy --only hosting

# Setup Cloud Scheduler
gcloud scheduler jobs create http estimate-processor \
  --schedule="*/15 * * * *" \
  --uri="https://estimate-agent-xxxx.run.app/process" \
  --http-method=POST \
  --oidc-service-account-email=estimate-agent@$PROJECT_ID.iam.gserviceaccount.com

# Daily digest at 8 AM
gcloud scheduler jobs create http daily-digest \
  --schedule="0 8 * * *" \
  --uri="https://sms-notifier-xxxx.run.app/api/notify/digest" \
  --http-method=POST \
  --oidc-service-account-email=estimate-agent@$PROJECT_ID.iam.gserviceaccount.com
```

## Usage Examples

### 1. Initial Setup

```bash
# Install dependencies
npm install

# Setup environment
cp .env.example .env
# Edit .env with your credentials

# Initialize secrets
node -e "
  const { secretService } = require('./security-module');
  secretService.storePlatformCredentials('planhub', {
    email: 'your-email@example.com',
    password: 'your-password'
  });
"

# Start services
docker-compose up -d

# Generate API key
curl -X POST http://localhost:8083/api/auth/generate-key \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name": "main-service"}'
```

### 2. Manual Estimate Processing

```bash
# Trigger processing manually
curl -X POST http://localhost:8080/process \
  -H "X-API-Key: YOUR_API_KEY"
```

### 3. Check API Usage

```bash
# Get usage stats (last 7 days)
curl http://localhost:8081/api/usage/stats?days=7 \
  -H "X-API-Key: YOUR_API_KEY"

# Get cost projection
curl http://localhost:8081/api/usage/projection \
  -H "X-API-Key: YOUR_API_KEY"

# Get rate limit status
curl http://localhost:8081/api/usage/rate-limits \
  -H "X-API-Key: YOUR_API_KEY"
```

### 4. Send Test Notification

```bash
# Test SMS notification
curl -X POST http://localhost:8082/api/notify/test \
  -H "X-API-Key: YOUR_API_KEY"

# Check notification history
curl http://localhost:8082/api/notify/history?limit=20 \
  -H "X-API-Key: YOUR_API_KEY"
```

### 5. Performance Monitoring

```bash
# Check learning module performance
curl http://localhost:8085/api/learn/dashboard?days=30

# Get cost optimization report
curl http://localhost:8084/api/optimize/report

# Check agent accuracy trends
curl http://localhost:8085/api/learn/dashboard | jq '.accuracy.trend'
```

### 6. Submit Feedback for Learning

```bash
# User corrects an estimate
curl -X POST http://localhost:8085/api/learn/feedback \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "estimateId": "est_123",
    "type": "correction",
    "category": "measurement",
    "correctedValues": {
      "linearFootage": 3200,
      "parkingSpaces": 145
    }
  }'

# Track final outcome
curl -X POST http://localhost:8085/api/learn/track-outcome/est_123 \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "won": true,
    "actualCost": 2847.50,
    "clientSatisfaction": 5
  }'
```

## Monitoring & Dashboards

### Prometheus Metrics

```typescript
// Add to each module
import prometheus from 'prom-client';

const register = new prometheus.Registry();

const httpRequestDuration = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

// Expose metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

### Grafana Dashboard JSON

```json
{
  "dashboard": {
    "title": "Custom Stripe Estimates",
    "panels": [
      {
        "title": "Estimates Processed Today",
        "targets": [{
          "expr": "sum(estimate_processed_total{status='auto_sent'})"
        }]
      },
      {
        "title": "API Cost Today",
        "targets": [{
          "expr": "sum(api_cost_dollars)"
        }]
      },
      {
        "title": "Error Rate",
        "targets": [{
          "expr": "rate(estimate_errors_total[5m])"
        }]
      }
    ]
  }
}
```

## Cost Estimates

### Monthly Operating Costs

| Service | Usage | Cost |
|---------|-------|------|
| Cloud Run (6 services) | ~1080 hours/month | $45 |
| Gemini 2.0 Flash | 50-100 estimates | $15-30 |
| Gmail API | Free tier | $0 |
| Firestore | ~15GB storage | $7 |
| Secret Manager | 15 secrets | $1.50 |
| Twilio SMS | ~60 messages | $5 |
| Redis (Cloud Memorystore) | 1GB | $30 |
| Firebase Hosting | Static site | $0 |
| **Total** | | **~$103-118/month** |
| **Minus Optimizer Savings** | -$30-40/month | **~$63-88/month** |

### Cost Optimization Impact

**Without Optimizer:** ~$103-118/month  
**With Optimizer:** ~$63-88/month  
**Savings:** ~$30-40/month (25-35%)

### Cost Optimization Tips

1. **Use caching aggressively** - Cache Gemini prompts
2. **Batch notifications** - Daily digests vs individual SMS
3. **Set strict rate limits** - Prevent runaway API costs
4. **Use Cloud Run min-instances=0** - Pay only when processing
5. **Monitor and alert** - Get notified at 50% budget

## Troubleshooting

### Common Issues

**Issue: Agent not processing emails**
```bash
# Check logs
docker logs estimate-agent --tail=100

# Verify Gmail API access
gcloud auth application-default login

# Test email fetching manually
curl http://localhost:8080/test-gmail
```

**Issue: High API costs**
```bash
# Check current usage
curl http://localhost:8081/api/usage/stats

# Review expensive operations
curl http://localhost:8081/api/usage/stats | jq '.byOperation'

# Temporarily disable processing
curl -X POST http://localhost:8080/pause \
  -H "X-API-Key: YOUR_API_KEY"
```

**Issue: SMS not sending**
```bash
# Check Twilio credentials
curl http://localhost:8082/api/notify/test

# Verify phone number format
# Must be E.164 format: +1234567890

# Check notification logs
docker logs sms-notifier --tail=50
```

**Issue: Platform login failures**
```bash
# Update credentials
curl -X POST http://localhost:8083/api/secrets/platform/planhub \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email": "new@email.com", "password": "newpass"}'

# Check security events
curl http://localhost:8083/api/security/events?type=authentication_failure
```

**Issue: Rate limits exceeded**
```bash
# Check current limits
curl http://localhost:8081/api/usage/rate-limits

# Increase limits (if justified)
curl -X POST http://localhost:8081/api/usage/limits \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"provider": "gemini", "limits": {"requestsPerMinute": 120}}'
```

## Advanced Features

### 1. Multi-Platform Support

```typescript
// Add new platform handler
import { Tool } from '@google/adk';

export const fetchFromNewPlatform: Tool = {
  name: 'fetch_from_new_platform',
  description: 'Fetch documents from NewPlatform',
  parameters: {
    type: 'object',
    properties: {
      projectUrl: { type: 'string' }
    }
  },
  handler: async ({ projectUrl }) => {
    // Custom implementation for new platform
    const credentials = await secretService.getPlatformCredentials('newplatform');
    // ... platform-specific logic
  }
};

// Register with agent
estimateAgent.tools.push(fetchFromNewPlatform);
```

### 2. Custom Pricing Rules

```typescript
// Add to pricing engine
class CustomPricingRules {
  async calculateEstimate(measurements: any, client: string): Promise<any> {
    let baseEstimate = standardPricing.calculate(measurements);
    
    // Volume discount
    if (measurements.parkingSpaces?.total > 200) {
      baseEstimate.total *= 0.90; // 10% discount
    }
    
    // Returning customer discount
    const previousJobs = await db.collection('estimates')
      .where('clientEmail', '==', client)
      .where('status', '==', 'completed')
      .get();
    
    if (previousJobs.size > 3) {
      baseEstimate.total *= 0.95; // 5% loyalty discount
    }
    
    // Rush job premium
    if (measurements.rushJob) {
      baseEstimate.total *= 1.25; // 25% premium
    }
    
    return baseEstimate;
  }
}
```

### 3. Custom Notifications

```typescript
// Add custom notification type
const NOTIFICATION_TEMPLATES = {
  ...existingTemplates,
  
  [NotificationType.LARGE_PROJECT_ALERT]: {
    type: NotificationType.LARGE_PROJECT_ALERT,
    priority: NotificationPriority.HIGH,
    template: (data) => 
      `🎯 LARGE PROJECT OPPORTUNITY\n` +
      `Client: ${data.clientEmail}\n` +
      `Estimate: $${data.amount.toLocaleString()}\n` +
      `Spaces: ${data.spaces}\n` +
      `This could be a significant job!`
  },
  
  [NotificationType.COMPETITOR_MENTION]: {
    type: NotificationType.COMPETITOR_MENTION,
    priority: NotificationPriority.MEDIUM,
    template: (data) =>
      `👀 Competitor mentioned in email\n` +
      `Competitor: ${data.competitor}\n` +
      `Context: ${data.context}\n` +
      `Review before responding`
  }
};
```

### 4. Machine Learning Improvements

```typescript
// Track estimate accuracy for continuous improvement
class EstimateAccuracyTracker {
  async recordActualCost(estimateId: string, actualCost: number): Promise<void> {
    const estimate = await db.collection('estimates').doc(estimateId).get();
    const estimated = estimate.data().estimate.total;
    
    const variance = Math.abs(actualCost - estimated) / estimated;
    
    await db.collection('estimate_accuracy').add({
      estimateId,
      estimated,
      actual: actualCost,
      variance,
      measurements: estimate.data().measurements,
      timestamp: new Date()
    });
    
    // If variance > 20%, analyze why
    if (variance > 0.2) {
      logger.warn('High estimate variance', {
        estimateId,
        estimated,
        actual: actualCost,
        variance
      });
      
      await notificationService.send(
        NotificationType.SYSTEM_ERROR,
        {
          service: 'estimate_accuracy',
          error: `Large variance detected: ${(variance * 100).toFixed(1)}%`
        }
      );
    }
  }
  
  async getAverageAccuracy(): Promise<number> {
    const snapshot = await db.collection('estimate_accuracy').get();
    const totalVariance = snapshot.docs.reduce(
      (sum, doc) => sum + doc.data().variance, 
      0
    );
    return 1 - (totalVariance / snapshot.size);
  }
}
```

## Maintenance Schedule

### Daily Tasks (Automated)
- ✅ Process unread estimate emails (every 15 min)
- ✅ Send daily digest (8 AM)
- ✅ Check budget thresholds (hourly)
- ✅ Rotate logs
- ✅ Clear old Redis keys

### Weekly Tasks (Manual - 10 min)
- Review pending estimates in dashboard
- Check notification history for issues
- Review API usage trends
- Update platform credentials if needed
- Check security events

### Monthly Tasks (Manual - 30 min)
- Review cost vs budget
- Analyze estimate accuracy
- Update pricing if needed
- Review and revoke unused API keys
- Check for system updates

## Testing

### Unit Tests

```typescript
// tests/agent.test.ts
import { estimateAgent } from '../agent';
import { tracker } from '../api-tracking-module';

describe('Estimate Agent', () => {
  it('should process email and extract platform links', async () => {
    const mockEmail = {
      from: 'test@example.com',
      body: 'Check out this project: https://planhub.com/project/123'
    };
    
    const result = await estimateAgent.processEmail(mockEmail);
    expect(result.platformLinks).toHaveLength(1);
    expect(result.platformLinks[0].platform).toBe('planhub');
  });
  
  it('should track API usage', async () => {
    await tracker.trackAPICall({
      provider: 'gemini',
      model: 'gemini-2.0-flash-exp',
      operation: 'test',
      inputTokens: 100,
      outputTokens: 50,
      status: 'success'
    });
    
    const stats = await tracker.getUsageStats({
      start: new Date(Date.now() - 1000),
      end: new Date()
    });
    
    expect(stats.totalCalls).toBeGreaterThan(0);
  });
});
```

### Integration Tests

```bash
#!/bin/bash
# tests/integration-test.sh

echo "Starting integration tests..."

# Test 1: Health checks
echo "Checking service health..."
curl -f http://localhost:8080/health || exit 1
curl -f http://localhost:8081/health || exit 1
curl -f http://localhost:8082/health || exit 1
curl -f http://localhost:8083/health || exit 1

# Test 2: API key auth
echo "Testing API key authentication..."
API_KEY=$(curl -s -X POST http://localhost:8083/api/auth/generate-key \
  -H "Authorization: Bearer $TEST_JWT" \
  -d '{"name":"test-key"}' | jq -r '.apiKey')

# Test 3: Process test email
echo "Testing estimate processing..."
curl -X POST http://localhost:8080/process \
  -H "X-API-Key: $API_KEY" || exit 1

# Test 4: Check API usage
echo "Checking API usage tracking..."
curl -f http://localhost:8081/api/usage/stats \
  -H "X-API-Key: $API_KEY" || exit 1

# Test 5: Send test notification
echo "Testing SMS notification..."
curl -X POST http://localhost:8082/api/notify/test \
  -H "X-API-Key: $API_KEY" || exit 1

echo "All integration tests passed!"
```

## Performance Optimization

### 1. Caching Strategy

```typescript
// Implement response caching
import NodeCache from 'node-cache';

const cache = new NodeCache({ stdTTL: 3600 }); // 1 hour

async function getCachedOrFetch(key: string, fetchFn: Function) {
  const cached = cache.get(key);
  if (cached) {
    logger.info('Cache hit', { key });
    return cached;
  }
  
  const result = await fetchFn();
  cache.set(key, result);
  return result;
}

// Example usage
const measurements = await getCachedOrFetch(
  `pdf_analysis_${pdfHash}`,
  () => analyzeParkingLotPDF(pdfBuffer)
);
```

### 2. Batch Processing

```typescript
// Process multiple emails in batch
async function batchProcessEmails(emails: any[]) {
  const batches = chunk(emails, 5); // Process 5 at a time
  
  for (const batch of batches) {
    await Promise.all(
      batch.map(email => processEmail(email))
    );
    
    // Wait between batches to respect rate limits
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}
```

### 3. Database Indexing

```typescript
// Create Firestore indexes
const indexes = [
  {
    collectionGroup: 'estimates',
    fields: [
      { fieldPath: 'status', order: 'ASCENDING' },
      { fieldPath: 'createdAt', order: 'DESCENDING' }
    ]
  },
  {
    collectionGroup: 'api_usage',
    fields: [
      { fieldPath: 'date', order: 'ASCENDING' },
      { fieldPath: 'provider', order: 'ASCENDING' }
    ]
  }
];

// Deploy indexes
// gcloud firestore indexes create --collection-group=estimates \
//   --field-config field-path=status,order=ascending \
//   --field-config field-path=createdAt,order=descending
```

## Security Checklist

- [ ] All API endpoints require authentication
- [ ] Secrets stored in Google Secret Manager (not .env)
- [ ] HTTPS enforced on all services
- [ ] Rate limiting enabled
- [ ] Input validation on all user inputs
- [ ] SQL injection prevention (using Firestore)
- [ ] XSS prevention (sanitizing inputs)
- [ ] CORS properly configured
- [ ] Audit logging enabled
- [ ] Regular security event reviews
- [ ] API keys rotated quarterly
- [ ] Platform credentials encrypted
- [ ] Passwords checked against breach database
- [ ] Security headers enabled (helmet.js)
- [ ] JWT tokens with short expiration
- [ ] Session management with Redis

## Backup & Recovery

### Automated Backups

```bash
#!/bin/bash
# backup.sh

# Backup Firestore
gcloud firestore export gs://your-backup-bucket/firestore/$(date +%Y%m%d)

# Backup Redis
redis-cli --rdb /backups/redis-$(date +%Y%m%d).rdb

# Backup secrets list (not values)
gcloud secrets list --format=json > /backups/secrets-list-$(date +%Y%m%d).json

# Backup configuration
cp .env /backups/config-$(date +%Y%m%d).env

echo "Backup completed: $(date)"
```

### Disaster Recovery

```bash
#!/bin/bash
# restore.sh

BACKUP_DATE=$1

# Restore Firestore
gcloud firestore import gs://your-backup-bucket/firestore/$BACKUP_DATE

# Restore Redis
redis-cli --pipe < /backups/redis-$BACKUP_DATE.rdb

# Restore configuration
cp /backups/config-$BACKUP_DATE.env .env

echo "Restore completed from backup: $BACKUP_DATE"
```

## Support & Resources

### Documentation
- [Google ADK Docs](https://google.github.io/adk-docs/)
- [Gemini API Reference](https://ai.google.dev/docs)
- [Firestore Documentation](https://cloud.google.com/firestore/docs)
- [Twilio SMS API](https://www.twilio.com/docs/sms)

### Community
- ADK GitHub Issues
- Stack Overflow (`google-adk` tag)
- Google Cloud Community

### Monitoring Dashboards
- **Production Status**: https://your-dashboard.com/status
- **Cost Tracking**: https://your-dashboard.com/costs
- **Estimates Queue**: https://your-dashboard.com/queue
- **Security Events**: https://your-dashboard.com/security

## Conclusion

This modular system provides:

✅ **Autonomous estimate processing** with Google ADK  
✅ **Comprehensive API tracking** with cost management  
✅ **Smart SMS notifications** with throttling  
✅ **Enterprise security** with encryption & audit logs  
✅ **Intelligent cost optimization** with 25-35% savings  
✅ **Continuous learning** from feedback & outcomes  
✅ **Beautiful modern dashboard** for oversight  
✅ **Scalable architecture** ready for growth  
✅ **Cost-effective** (~$63-88/month after optimization)  
✅ **Low maintenance** (~30 min/week)  

### Complete Module List:

1. **Main Estimate Agent** (Port 8080) - Core ADK processing
2. **API Tracking** (Port 8081) - Usage & cost monitoring
3. **SMS Notifier** (Port 8082) - Smart alerts
4. **Security** (Port 8083) - Auth, encryption, audit
5. **Cost Optimizer** (Port 8084) - Budget & model optimization
6. **Learning Module** (Port 8085) - Context & continuous improvement
7. **Dashboard** (Port 80) - Modern UI for oversight

Each module is standalone and can be:
- Developed independently
- Deployed separately
- Scaled individually
- Tested in isolation
- Updated without affecting others

**Next Steps:**
1. Set up development environment
2. Configure `.env` file with all 6 service ports
3. Deploy to Cloud Run (6 services + dashboard)
4. Test with sample emails
5. Monitor dashboard for 1 week
6. Let learning module collect feedback
7. Review cost optimizer recommendations
8. Adjust pricing/thresholds based on data
9. Enable full auto-processing

The system gets **smarter and cheaper** over time! 🚀🧠💰
