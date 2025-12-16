# Deployment Checklist for MOBL-3244

## Pre-Deployment

### Database Setup
- [ ] Create DynamoDB `UserFeedback` table with indexes
- [ ] Create DynamoDB `UserMetrics` table with indexes
- [ ] Verify table permissions in IAM role
- [ ] Enable encryption at rest
- [ ] Configure backup/recovery

### Environment Configuration
- [ ] Set `JWT_SECRET` environment variable
- [ ] Configure `APPLE_CLIENT_ID`
- [ ] Configure `APPLE_TEAM_ID`
- [ ] Configure `APPLE_KEY_ID`
- [ ] Configure `APPLE_PRIVATE_KEY`
- [ ] Update API Gateway CORS settings for production domains

### Backend Build
- [ ] Run tests: `cd submitImage && go test ./... -v`
- [ ] Build Lambda: `GOOS=linux GOARCH=amd64 go build -o bootstrap main.go`
- [ ] Verify all dependencies in `go.mod`
- [ ] Run `sam validate` on template.yml

### Frontend Build
- [ ] Run tests: `npm test`
- [ ] Set production API URL: `REACT_APP_API_BASE_URL`
- [ ] Build: `npm run build`
- [ ] Verify bundle size
- [ ] Test accessibility with screen reader

## Deployment

### AWS SAM Deployment
```bash
sam build
sam deploy --guided
```

### Post-Deployment Verification
- [ ] Test POST /feedback endpoint
- [ ] Test GET /feedback endpoint
- [ ] Test POST /metrics/track endpoint
- [ ] Verify JWT authentication works
- [ ] Check CORS headers
- [ ] Monitor CloudWatch logs for errors

### Frontend Deployment
- [ ] Deploy build directory to hosting
- [ ] Verify API connectivity
- [ ] Test feedback form submission
- [ ] Test metrics tracking
- [ ] Verify responsive design on mobile

## Testing in Production

### Functional Tests
- [ ] Submit bug report feedback
- [ ] Submit feature request feedback
- [ ] Submit feedback with rating
- [ ] Submit feedback with email
- [ ] Retrieve feedback history
- [ ] Track page view event
- [ ] Track user action event
- [ ] Verify error tracking

### Performance Tests
- [ ] API response time < 2 seconds
- [ ] Frontend loads < 3 seconds
- [ ] No memory leaks in browser
- [ ] DynamoDB not throttling

### Security Tests
- [ ] Unauthorized requests return 401
- [ ] Invalid tokens rejected
- [ ] Input validation works
- [ ] XSS protection in place
- [ ] CSRF protection enabled

## Monitoring Setup

### CloudWatch Alarms
- [ ] High error rate alarm (>5%)
- [ ] High latency alarm (>3s)
- [ ] DynamoDB throttling alarm
- [ ] Lambda concurrent execution alarm

### Dashboards
- [ ] Create feedback metrics dashboard
- [ ] Create user engagement dashboard
- [ ] Create performance dashboard

## Documentation

- [ ] Update README.md with new features
- [ ] Share FEEDBACK_IMPLEMENTATION.md with team
- [ ] Update API documentation
- [ ] Add deployment notes to wiki
- [ ] Update Jira ticket with deployment info

## Rollback Plan

If issues occur:
1. Revert Lambda function to previous version
2. Restore previous SAM stack
3. Document issues encountered
4. Fix in development environment
5. Re-test before next deployment

## Success Criteria

- [ ] Users can submit feedback without errors
- [ ] Metrics are being collected successfully
- [ ] API responds within 2 seconds
- [ ] UI is accessible on all devices
- [ ] No critical errors in CloudWatch logs
- [ ] Authentication works correctly
- [ ] Data is persisted to DynamoDB
