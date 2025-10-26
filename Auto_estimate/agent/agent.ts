// ===================================================================
// ADK PARKING LOT ESTIMATE AGENT - COMPLETE IMPLEMENTATION
// Custom Stripe Texas - Autonomous Email Processing System
// ===================================================================

import { Agent, Tool } from '@google/adk';
import { google } from 'googleapis';
import { Firestore } from '@google-cloud/firestore';
import { GoogleGenerativeAI } from '@google/generative-ai';
import puppeteer from 'puppeteer';
import express from 'express';
import winston from 'winston';
import * as Sentry from '@sentry/node';
import { Poppler } from 'pdf-poppler';
import * as fs from 'fs';
import * as path from 'path';

// ===================================================================
// LOGGING CONFIGURATION
// ===================================================================

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ 
      filename: 'error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'combined.log',
      maxsize: 5242880,
      maxFiles: 10
    })
  ]
});

// Sentry for error tracking
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV || 'development',
  tracesSampleRate: 1.0
});

// ===================================================================
// ERROR HANDLING UTILITIES
// ===================================================================

class RetryableError extends Error {
  constructor(message: string, public retryable: boolean = true) {
    super(message);
    this.name = 'RetryableError';
  }
}

class ValidationError extends Error {
  constructor(message: string, public issues: string[]) {
    super(message);
    this.name = 'ValidationError';
  }
}

async function withRetry<T>(
  fn: () => Promise<T>,
  options: {
    maxAttempts?: number;
    delay?: number;
    backoff?: number;
    context?: string;
  } = {}
): Promise<T> {
  const { 
    maxAttempts = 3, 
    delay = 1000, 
    backoff = 2,
    context = 'operation' 
  } = options;

  let lastError: Error;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      logger.info(`${context}: Attempt ${attempt}/${maxAttempts}`);
      const result = await fn();
      
      if (attempt > 1) {
        logger.info(`${context}: Succeeded on attempt ${attempt}`);
      }
      
      return result;
    } catch (error) {
      lastError = error;
      
      logger.warn(`${context}: Attempt ${attempt} failed`, {
        error: error.message,
        stack: error.stack
      });

      if (error instanceof RetryableError && !error.retryable) {
        logger.error(`${context}: Non-retryable error, aborting`, { error });
        throw error;
      }

      if (attempt < maxAttempts) {
        const waitTime = delay * Math.pow(backoff, attempt - 1);
        logger.info(`${context}: Waiting ${waitTime}ms before retry`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }

  logger.error(`${context}: All ${maxAttempts} attempts failed`, {
    error: lastError.message
  });
  
  Sentry.captureException(lastError, {
    tags: { context, attempts: maxAttempts }
  });
  
  throw lastError;
}

// ===================================================================
// INITIALIZATION
// ===================================================================

const db = new Firestore();
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_API_KEY);

async function getGmailClient() {
  const auth = new google.auth.GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/gmail.modify']
  });
  const authClient = await auth.getClient();
  return google.gmail({ version: 'v1', auth: authClient });
}

function getHeader(message: any, headerName: string): string {
  const header = message.payload?.headers?.find(
    h => h.name.toLowerCase() === headerName.toLowerCase()
  );
  return header?.value || '';
}

function getEmailBody(message: any): string {
  let body = '';
  
  function extractBody(part: any) {
    if (part.mimeType === 'text/plain' || part.mimeType === 'text/html') {
      if (part.body?.data) {
        body += Buffer.from(part.body.data, 'base64').toString('utf-8');
      }
    }
    if (part.parts) {
      part.parts.forEach(extractBody);
    }
  }
  
  if (message.payload) {
    extractBody(message.payload);
  }
  
  return body;
}

// ===================================================================
// EMAIL TOOLS
// ===================================================================

export const getUnreadEstimateEmails: Tool = {
  name: 'get_unread_estimate_emails',
  description: 'Retrieves unread emails from Gmail that appear to be construction estimate requests',
  parameters: {
    type: 'object',
    properties: {
      maxResults: {
        type: 'number',
        description: 'Maximum number of emails to retrieve',
        default: 10
      }
    }
  },
  handler: async ({ maxResults = 10 }) => {
    return withRetry(
      async () => {
        logger.info('Fetching unread estimate emails', { maxResults });
        
        const gmail = await getGmailClient();
        const response = await gmail.users.messages.list({
          userId: 'me',
          q: 'is:unread (estimate OR proposal OR bid OR RFP) (parking OR striping)',
          maxResults
        });

        if (!response.data.messages || response.data.messages.length === 0) {
          logger.info('No unread estimate emails found');
          return { emails: [] };
        }

        const emails = [];
        for (const message of response.data.messages) {
          try {
            const full = await gmail.users.messages.get({
              userId: 'me',
              id: message.id,
              format: 'full'
            });
            
            emails.push({
              id: full.data.id,
              threadId: full.data.threadId,
              from: getHeader(full.data, 'From'),
              subject: getHeader(full.data, 'Subject'),
              date: getHeader(full.data, 'Date'),
              body: getEmailBody(full.data)
            });
            
            logger.info('Fetched email', {
              emailId: full.data.id,
              from: getHeader(full.data, 'From'),
              subject: getHeader(full.data, 'Subject')
            });
          } catch (error) {
            logger.error('Failed to fetch individual email', {
              messageId: message.id,
              error: error.message
            });
          }
        }

        logger.info(`Successfully fetched ${emails.length} emails`);
        return { emails };
      },
      { context: 'get_unread_estimate_emails', maxAttempts: 3 }
    );
  }
};

export const sendEmail: Tool = {
  name: 'send_email',
  description: 'Sends an email response with estimate details',
  parameters: {
    type: 'object',
    properties: {
      to: { type: 'string', description: 'Recipient email address' },
      subject: { type: 'string', description: 'Email subject line' },
      body: { type: 'string', description: 'Email body content (can include HTML)' },
      threadId: { type: 'string', description: 'Thread ID to reply to' }
    },
    required: ['to', 'subject', 'body']
  },
  handler: async ({ to, subject, body, threadId }) => {
    return withRetry(
      async () => {
        logger.info('Sending email', { to, subject, threadId });
        
        const gmail = await getGmailClient();
        
        const email = [
          `To: ${to}`,
          `Subject: ${subject}`,
          threadId ? `In-Reply-To: ${threadId}` : '',
          'Content-Type: text/html; charset=utf-8',
          '',
          body
        ].filter(Boolean).join('\r\n');

        const encoded = Buffer.from(email)
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');

        await gmail.users.messages.send({
          userId: 'me',
          requestBody: {
            raw: encoded,
            threadId
          }
        });

        logger.info('Email sent successfully', { to, subject });
        return { success: true, sentTo: to };
      },
      { context: 'send_email', maxAttempts: 2 }
    );
  }
};

export const markEmailAsProcessed: Tool = {
  name: 'mark_email_processed',
  description: 'Marks an email as read and applies a label',
  parameters: {
    type: 'object',
    properties: {
      emailId: { type: 'string', description: 'Email ID to mark' },
      label: { type: 'string', description: 'Label to apply', default: 'Processed' }
    },
    required: ['emailId']
  },
  handler: async ({ emailId, label = 'Processed' }) => {
    return withRetry(
      async () => {
        logger.info('Marking email as processed', { emailId, label });
        
        const gmail = await getGmailClient();
        
        // Get or create label
        const labels = await gmail.users.labels.list({ userId: 'me' });
        let labelId = labels.data.labels?.find(l => l.name === label)?.id;
        
        if (!labelId) {
          logger.info('Creating new label', { label });
          const created = await gmail.users.labels.create({
            userId: 'me',
            requestBody: { name: label }
          });
          labelId = created.data.id;
        }

        await gmail.users.messages.modify({
          userId: 'me',
          id: emailId,
          requestBody: {
            removeLabelIds: ['UNREAD'],
            addLabelIds: [labelId]
          }
        });

        logger.info('Email marked as processed', { emailId, label });
        return { success: true };
      },
      { context: 'mark_email_processed', maxAttempts: 2 }
    );
  }
};

// ===================================================================
// DOCUMENT TOOLS
// ===================================================================

export const extractPlatformLinks: Tool = {
  name: 'extract_platform_links',
  description: 'Extracts construction platform links from email body',
  parameters: {
    type: 'object',
    properties: {
      emailBody: { type: 'string', description: 'Email body text or HTML' }
    },
    required: ['emailBody']
  },
  handler: async ({ emailBody }) => {
    try {
      logger.info('Extracting platform links from email');
      
      const platformPatterns = {
        planhub: /https?:\/\/(?:app\.)?planhub\.com\/[^\s<>"]+/gi,
        buildingConnected: /https?:\/\/(?:app\.)?buildingconnected\.com\/[^\s<>"]+/gi,
        constructConnect: /https?:\/\/(?:www\.)?constructconnect\.com\/[^\s<>"]+/gi,
        isqft: /https?:\/\/(?:www\.)?isqft\.com\/[^\s<>"]+/gi,
      };

      const links = [];
      for (const [platform, pattern] of Object.entries(platformPatterns)) {
        const matches = emailBody.match(pattern);
        if (matches) {
          matches.forEach(url => {
            links.push({ platform, url: url.trim() });
            logger.info('Found platform link', { platform, url });
          });
        }
      }

      logger.info(`Extracted ${links.length} platform links`);
      return { links };
    } catch (error) {
      logger.error('Failed to extract platform links', { error: error.message });
      return { links: [], error: error.message };
    }
  }
};

export const fetchDocumentsFromPlatform: Tool = {
  name: 'fetch_documents_from_platform',
  description: 'Navigates to a construction platform and downloads project documents',
  parameters: {
    type: 'object',
    properties: {
      platformUrl: { type: 'string', description: 'URL to the project' },
      platform: { type: 'string', description: 'Platform name' }
    },
    required: ['platformUrl', 'platform']
  },
  handler: async ({ platformUrl, platform }) => {
    return withRetry(
      async () => {
        logger.info('Fetching documents from platform', { platform, platformUrl });
        
        const browser = await puppeteer.launch({ 
          headless: true,
          args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        
        try {
          const page = await browser.newPage();
          
          // Set viewport and user agent
          await page.setViewport({ width: 1920, height: 1080 });
          await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0');
          
          // Load credentials if needed
          const credKey = `platform_credentials_${platform}`;
          const credDoc = await db.collection('config').doc(credKey).get();
          
          if (credDoc.exists) {
            logger.info('Found credentials for platform', { platform });
            const credentials = credDoc.data();
            await loginToPlatform(page, platform, credentials);
          }
          
          // Navigate to project with timeout
          await page.goto(platformUrl, { 
            waitUntil: 'networkidle2',
            timeout: 30000 
          });
          
          logger.info('Page loaded, searching for documents');
          
          // Find document links
          const documents = await page.evaluate(() => {
            const links = [];
            const selectors = [
              'a[href*=".pdf"]',
              'a[href*="/download/"]',
              '.document-link',
              '[data-testid*="document"]',
              'a[href*="plan"]',
              'a[href*="spec"]'
            ];
            
            selectors.forEach(selector => {
              document.querySelectorAll(selector).forEach(link => {
                const text = link.textContent?.toLowerCase() || '';
                const href = link.getAttribute('href');
                
                if (href && (
                  text.includes('plan') || 
                  text.includes('site') || 
                  text.includes('parking') ||
                  text.includes('drawing') ||
                  href.includes('.pdf')
                )) {
                  links.push({
                    url: link.href,
                    title: link.textContent?.trim() || 'Untitled',
                    type: href.endsWith('.pdf') ? 'pdf' : 'link'
                  });
                }
              });
            });
            
            return links;
          });
          
          logger.info(`Found ${documents.length} documents on platform`);
          
          // Download PDFs
          const downloadedDocs = [];
          for (const doc of documents.slice(0, 5)) { // Limit to 5 docs
            if (doc.type === 'pdf') {
              try {
                logger.info('Downloading PDF', { title: doc.title });
                const pdfResponse = await page.goto(doc.url, { timeout: 60000 });
                const pdfBuffer = await pdfResponse.buffer();
                
                downloadedDocs.push({
                  title: doc.title,
                  buffer: pdfBuffer.toString('base64'),
                  mimeType: 'application/pdf',
                  size: pdfBuffer.length
                });
                
                logger.info('PDF downloaded', { 
                  title: doc.title, 
                  size: pdfBuffer.length 
                });
              } catch (error) {
                logger.error('Failed to download PDF', {
                  title: doc.title,
                  error: error.message
                });
              }
            }
          }
          
          await browser.close();
          
          return { 
            documents: downloadedDocs,
            projectUrl: platformUrl 
          };
          
        } catch (error) {
          await browser.close();
          logger.error('Error fetching documents from platform', {
            platform,
            error: error.message,
            stack: error.stack
          });
          throw new RetryableError(`Failed to fetch documents: ${error.message}`);
        }
      },
      { 
        context: `fetch_documents_${platform}`, 
        maxAttempts: 2,
        delay: 2000 
      }
    );
  }
};

async function loginToPlatform(page: any, platform: string, credentials: any) {
  logger.info('Attempting login', { platform });
  
  try {
    switch (platform) {
      case 'planhub':
        await page.goto('https://app.planhub.com/login');
        await page.type('#email', credentials.email);
        await page.type('#password', credentials.password);
        await page.click('.login-button');
        await page.waitForNavigation({ timeout: 15000 });
        break;
        
      case 'buildingconnected':
        await page.goto('https://app.buildingconnected.com/login');
        await page.type('input[type="email"]', credentials.email);
        await page.type('input[type="password"]', credentials.password);
        await page.click('button[type="submit"]');
        await page.waitForNavigation({ timeout: 15000 });
        break;
    }
    
    logger.info('Login successful', { platform });
  } catch (error) {
    logger.error('Login failed', { platform, error: error.message });
    throw new RetryableError(`Login failed for ${platform}`, false);
  }
}

async function convertPDFToImages(pdfBuffer: Buffer): Promise<Buffer[]> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-'));
  const pdfPath = path.join(tmpDir, 'input.pdf');
  fs.writeFileSync(pdfPath, pdfBuffer);

  const poppler = new Poppler();
  const options = {
    firstPageToConvert: 1,
    lastPageToConvert: 5, // Limit to 5 pages
    pngFile: true
  };
  await poppler.pdfToCairo(pdfPath, path.join(tmpDir, 'page'), options);

  const images: Buffer[] = [];
  for (let i = options.firstPageToConvert; i <= options.lastPageToConvert; i++) {
    const imgPath = path.join(tmpDir, `page-${i}.png`);
    if (fs.existsSync(imgPath)) {
      images.push(fs.readFileSync(imgPath));
    }
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
  return images;
}

// ===================================================================
// ANALYSIS TOOLS
// ===================================================================

export const analyzeParkingLotPDF: Tool = {
  name: 'analyze_parking_lot_pdf',
  description: 'Analyzes parking lot construction plans to extract measurements',
  parameters: {
    type: 'object',
    properties: {
      pdfBase64: { type: 'string', description: 'Base64 encoded PDF' },
      documentTitle: { type: 'string', description: 'Document title' }
    },
    required: ['pdfBase64']
  },
  handler: async ({ pdfBase64, documentTitle = 'Unknown' }) => {
    return withRetry(
      async () => {
        logger.info('Analyzing PDF', { documentTitle });
        
        // Convert PDF to images
        const pdfBuffer = Buffer.from(pdfBase64, 'base64');
        const images = await convertPDFToImages(pdfBuffer);
        
        logger.info(`PDF converted to ${images.length} images`);
        
        const model = genAI.getGenerativeModel({ 
          model: 'gemini-1.5-flash-exp'
        });

        const parts = [
          {
            text: `
              Analyze these parking lot construction plan pages.
              
              Extract precise measurements for:
              1. LINEAR FOOTAGE - Total striping needed (parking spaces + aisles)
              2. SQUARE FOOTAGE - Total lot area
              3. PARKING SPACES - Count and dimensions
              4. HANDICAP SPACES - Count (look for wheelchair symbols)
              5. FIRE LANES - Linear footage
              6. PARKING BUMPERS - Count needed
              
              Return JSON:
              {
                "measurements": {
                  "linearFootage": {"value": number, "confidence": 0-1, "notes": ""},
                  "squareFootage": {"value": number, "confidence": 0-1, "notes": ""},
                  "parkingSpaces": {"total": number, "handicap": number, "confidence": 0-1},
                  "fireLanes": {"linearFeet": number, "confidence": 0-1},
                  "parkingBumpers": {"count": number, "confidence": 0-1}
                },
                "scale": "drawing scale",
                "overallConfidence": 0-1,
                "clarificationsNeeded": []
              }
            `
          },
          ...images.map(img => ({
            inlineData: {
              mimeType: 'image/png',
              data: img.toString('base64')
            }
          }))
        ];

        const result = await model.generateContent({ parts });
        const analysis = JSON.parse(result.response.text());
        
        logger.info('PDF analysis complete', { documentTitle });
        
        return { analysis };
      },
      { context: 'analyze_parking_lot_pdf', maxAttempts: 1 }
    );
  }
};

export const createEstimate: Tool = {
  name: 'create_estimate',
  description: 'Creates a formal estimate document based on analysis',
  parameters: {
    type: 'object',
    properties: {
      analysis: { type: 'object', description: 'Analysis from analyze_parking_lot_pdf' },
      customerInfo: { type: 'object', description: 'Customer name, email, etc.' }
    },
    required: ['analysis', 'customerInfo']
  },
  handler: async ({ analysis, customerInfo }) => {
    // TODO: Implement PDF or document generation for the estimate
    logger.info('Creating estimate', { customer: customerInfo.name });
    return { estimateUrl: 'path/to/estimate.pdf' };
  }
};


// ===================================================================
// AGENT DEFINITION
// ===================================================================

const estimateAgent = new Agent({
  llm: genAI.getGenerativeModel({ model: 'gemini-1.5-flash-exp' }),
  tools: [
    getUnreadEstimateEmails,
    sendEmail,
    markEmailAsProcessed,
    extractPlatformLinks,
    fetchDocumentsFromPlatform,
    analyzeParkingLotPDF,
    createEstimate
  ],
  prompt: {
    system: `
      You are a construction estimator for a parking lot striping company.
      Your workflow:
      1. Find unread estimate requests in Gmail.
      2. For each email:
         - Extract links to construction platforms.
         - If links are found, fetch the documents (PDFs).
         - If no links, check for PDF attachments.
         - Analyze the most relevant PDF for parking lot measurements.
         - Create a formal estimate.
         - Send the estimate as a reply to the customer.
         - Mark the email as processed.
      Be methodical and log your progress.
    `
  }
});

// ===================================================================
// SERVER (Optional)
// ===================================================================

const app = express();
app.use(express.json());

app.post('/run', async (req, res) => {
  try {
    const { prompt } = req.body;
    const result = await estimateAgent.run(prompt);
    res.json(result);
  } catch (error) {
    logger.error('Agent run failed', { error: error.message });
    Sentry.captureException(error);
    res.status(500).json({ error: 'Agent failed to run' });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  logger.info(`Server listening on port ${port}`);
});
