# Quick Start Guide - MOBL-3244 Feedback & Metrics System

## 🚀 Getting Started in 5 Minutes

### Prerequisites
- AWS Account with DynamoDB access
- AWS SAM CLI installed
- Node.js 14+ and npm
- Go 1.x installed

### Step 1: Setup DynamoDB Tables (2 minutes)

```bash
# Create UserFeedback table
aws dynamodb create-table \
  --table-name UserFeedback \
  --attribute-definitions \
    AttributeName=Id,AttributeType=S \
    AttributeName=UserId,AttributeType=S \
    AttributeName=CreatedAt,AttributeType=S \
  --key-schema AttributeName=Id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --global-secondary-indexes \
    "[{\"IndexName\": \"UserIdIndex\",\"KeySchema\": [{\"AttributeName\":\"UserId\",\"KeyType\":\"HASH\"},{\"AttributeName\":\"CreatedAt\",\"KeyType\":\"RANGE\"}],\"Projection\": {\"ProjectionType\":\"ALL\"}}]"

# Create UserMetrics table
aws dynamodb create-table \
  --table-name UserMetrics \
  --attribute-definitions \
    AttributeName=Id,AttributeType=S \
    AttributeName=UserId,AttributeType=S \
    AttributeName=Timestamp,AttributeType=S \
  --key-schema AttributeName=Id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --global-secondary-indexes \
    "[{\"IndexName\": \"UserIdIndex\",\"KeySchema\": [{\"AttributeName\":\"UserId\",\"KeyType\":\"HASH\"},{\"AttributeName\":\"Timestamp\",\"KeyType\":\"RANGE\"}],\"Projection\": {\"ProjectionType\":\"ALL\"}}]"
```

### Step 2: Deploy Backend (2 minutes)

```bash
# Clean up duplicate files (IMPORTANT!)
rm -f submitImage/appleauth/apple_auth.improved.go
rm -f submitImage/main.improved.go

# Deploy
cd submitImage
sam build
sam deploy --guided
# Follow prompts, save config

# Note your API endpoint URL from outputs
```

### Step 3: Deploy Frontend (1 minute)

```bash
# Install dependencies
npm install

# Set your API URL
export REACT_APP_API_BASE_URL="https://your-api-id.execute-api.region.amazonaws.com/Prod"

# Build
npm run build

# Deploy build/ directory to your hosting (S3, Vercel, etc.)
```

## 📱 Using the Feedback System

### Option 1: Add Floating Feedback Button

```tsx
import { FeedbackButton } from './components/FeedbackButton';
import { MetricsTracker } from './components/MetricsTracker';

function App() {
  return (
    <MetricsTracker>
      <div className="app">
        {/* Your app content */}
        <h1>My App</h1>
        
        {/* Floating feedback button */}
        <FeedbackButton position="bottom-right" />
      </div>
    </MetricsTracker>
  );
}
```

### Option 2: Embed Feedback Form

```tsx
import { FeedbackForm } from './components/FeedbackForm';

function FeedbackPage() {
  return (
    <div>
      <h1>Share Your Feedback</h1>
      <FeedbackForm
        onSuccess={() => alert('Thank you!')}
        defaultCategory="general"
      />
    </div>
  );
}
```

### Option 3: Manual Metrics Tracking

```tsx
import { feedbackService } from './services/FeedbackService';

// Track any event
feedbackService.trackAction('button_clicked', { buttonId: 'submit' });

// Track page view (automatic with MetricsTracker)
feedbackService.trackPageView('/checkout');

// Track errors
try {
  // some code
} catch (error) {
  feedbackService.trackError(error, { context: 'payment' });
}
```

## 🧪 Testing

### Test Backend Locally

```bash
# Run tests
cd submitImage
go test ./opendevopslambda -v

# Test specific function
sam local invoke SubmitImageFunction -e test-event.json
```

### Test Frontend

```bash
# Run all tests
npm test

# Run with coverage
npm test -- --coverage
```

### Test API Endpoints

```bash
# Get your API URL
API_URL="https://your-api-id.execute-api.region.amazonaws.com/Prod"
TOKEN="your-jwt-token"

# Submit feedback
curl -X POST $API_URL/feedback \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "feedbackType": "bug",
    "title": "Test feedback",
    "message": "This is a test feedback message",
    "category": "general",
    "allowContact": false
  }'

# Get feedback
curl -X GET $API_URL/feedback \
  -H "Authorization: Bearer $TOKEN"

# Track metric
curl -X POST $API_URL/metrics/track \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "action",
    "eventName": "test_event",
    "properties": {"test": true}
  }'
```

## ⚙️ Configuration

### Environment Variables (Lambda)

Set in AWS Console → Lambda → Configuration → Environment variables:

```bash
JWT_SECRET=your-secret-key-here-change-in-production
APPLE_CLIENT_ID=your-apple-client-id
APPLE_TEAM_ID=your-apple-team-id
APPLE_KEY_ID=your-apple-key-id
APPLE_PRIVATE_KEY=your-apple-private-key-pem
```

### Environment Variables (Frontend)

Create `.env` file:

```bash
REACT_APP_API_BASE_URL=https://your-api-id.execute-api.region.amazonaws.com/Prod
```

## 🔍 Monitoring

### View Logs

```bash
# Lambda logs
sam logs -n SubmitImageFunction --tail

# Or in AWS Console
# CloudWatch → Log Groups → /aws/lambda/SubmitImageFunction
```

### Check DynamoDB

```bash
# View feedback
aws dynamodb scan --table-name UserFeedback --limit 10

# View metrics
aws dynamodb scan --table-name UserMetrics --limit 10
```

## 🐛 Troubleshooting

### Issue: Tests fail with "redeclared" errors

**Solution**: Remove `.improved.go` files:
```bash
rm submitImage/appleauth/apple_auth.improved.go
rm submitImage/main.improved.go
rm src/components/AppleLoginButton.improved.tsx
rm src/services/AppleAuthService.improved.ts
```

### Issue: 401 Unauthorized

**Solution**: 
- Check JWT token is valid
- Verify Authorization header: `Bearer <token>`
- Update JWT verification in `feedback_handler.go` for production

### Issue: CORS errors

**Solution**:
- Check API Gateway CORS settings
- Verify Access-Control-Allow-Origin headers
- Update template.yml CORS configuration

### Issue: DynamoDB errors

**Solution**:
- Verify tables exist: `aws dynamodb list-tables`
- Check Lambda IAM role has DynamoDB permissions
- Verify table names match code (UserFeedback, UserMetrics)

## 📊 Quick Metrics Query

### Get feedback count by type

```bash
aws dynamodb scan --table-name UserFeedback \
  --projection-expression "FeedbackType" \
  | jq -r '.Items[].FeedbackType.S' | sort | uniq -c
```

### Get recent feedback

```bash
aws dynamodb query --table-name UserFeedback \
  --index-name UserIdIndex \
  --key-condition-expression "UserId = :userId" \
  --expression-attribute-values '{":userId":{"S":"user_123"}}' \
  --limit 10 \
  --scan-index-forward false
```

## 🎯 Next Steps

1. ✅ Deploy to development environment
2. ✅ Test all features
3. ✅ Update JWT secret and verify authentication
4. ✅ Configure monitoring and alarms
5. ✅ Deploy to production
6. ✅ Monitor user feedback and metrics
7. ✅ Iterate based on feedback

## 📚 Documentation

- **Full Implementation Guide**: `FEEDBACK_IMPLEMENTATION.md`
- **Deployment Checklist**: `DEPLOYMENT_CHECKLIST.md`
- **Implementation Summary**: `IMPLEMENTATION_SUMMARY.md`
- **API Documentation**: `api.yaml` (OpenAPI 3.0)

## 💡 Tips

1. **Start with development environment** - Test thoroughly before production
2. **Set proper JWT_SECRET** - Use a strong, random secret in production
3. **Monitor costs** - DynamoDB on-demand pricing can add up with high traffic
4. **Rate limiting** - Configure at API Gateway to prevent abuse
5. **User privacy** - Email collection is optional, respect user preferences
6. **Feedback review** - Set up a process to review and act on feedback

## 🎉 You're Ready!

Your feedback and metrics system is now set up. Users can submit feedback, and you'll automatically track usage metrics.

**Need help?** Check the documentation or contact the resource owner (wmarusiak).
