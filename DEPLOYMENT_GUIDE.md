# User Registration System Deployment Guide

## Prerequisites

1. **AWS Account** with appropriate permissions
2. **AWS CLI** configured with credentials
3. **SAM CLI** installed for serverless deployment
4. **Go 1.16+** for local development and testing
5. **Verified SES Email Address** for sending emails

## Step-by-Step Deployment

### 1. Prepare AWS SES

Before deploying, you need to verify an email address in AWS SES:

```bash
# Verify your sender email address
aws ses verify-email-identity --email-address noreply@yourdomain.com

# Check verification status
aws ses get-identity-verification-attributes --identities noreply@yourdomain.com
```

### 2. Configure Parameters

Update the CloudFormation parameters in `template.yml` or create a parameters file:

```yaml
# parameters.json
{
  "FromEmail": "noreply@yourdomain.com",
  "BaseURL": "https://yourdomain.com"
}
```

### 3. Build and Deploy

```bash
# Navigate to the project directory
cd submitImage

# Build the Go application
sam build

# Deploy with guided setup (first time)
sam deploy --guided

# Or deploy with parameters file
sam deploy --parameter-overrides file://parameters.json
```

### 4. Configure Environment Variables

If not set during deployment, configure the Lambda environment variables:

```bash
# Get the function name from CloudFormation outputs
FUNCTION_NAME=$(aws cloudformation describe-stacks \
  --stack-name your-stack-name \
  --query 'Stacks[0].Outputs[?OutputKey==`SubmitImageFunctionName`].OutputValue' \
  --output text)

# Update environment variables
aws lambda update-function-configuration \
  --function-name $FUNCTION_NAME \
  --environment Variables='{
    "FROM_EMAIL":"noreply@yourdomain.com",
    "BASE_URL":"https://yourdomain.com"
  }'
```

### 5. Test the Deployment

```bash
# Get the API Gateway URL
API_URL=$(aws cloudformation describe-stacks \
  --stack-name your-stack-name \
  --query 'Stacks[0].Outputs[?OutputKey==`SubmitImageAPI`].OutputValue' \
  --output text)

# Test registration endpoint
curl -X POST $API_URL/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPass123!",
    "email": "test@yourdomain.com",
    "fullName": "Test User"
  }'
```

## Configuration Options

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `FROM_EMAIL` | Email address for sending notifications | `noreply@yourapp.com` | Yes |
| `BASE_URL` | Base URL for email verification links | `https://yourapp.com` | Yes |
| `APPLE_CLIENT_ID` | Apple authentication client ID | - | No |
| `APPLE_TEAM_ID` | Apple authentication team ID | - | No |
| `APPLE_KEY_ID` | Apple authentication key ID | - | No |
| `APPLE_PRIVATE_KEY` | Apple authentication private key | - | No |

### Rate Limiting Configuration

Rate limits are configured in the code and can be modified in `submitImage/userauth/rate_limiter.go`:

```go
// Registration rate limit: 3 attempts per 15 minutes
func GetDefaultRegistrationRateLimit() RateLimitConfig {
    return RateLimitConfig{
        MaxRequests: 3,
        Window:      15 * time.Minute,
        Endpoint:    "register",
    }
}
```

### Database Configuration

DynamoDB tables are automatically created with the following configuration:

- **Users Table**: Pay-per-request billing, GSI for email and token lookups
- **RateLimits Table**: Pay-per-request billing, TTL enabled for automatic cleanup

## Security Configuration

### 1. IAM Permissions

The Lambda function requires the following permissions:
- DynamoDB: Read/Write access to Users and RateLimits tables
- SES: Send email permissions
- CloudWatch: Logging permissions

### 2. API Gateway Security

Configure API Gateway with:
- CORS headers for web applications
- Request validation
- Rate limiting at the API Gateway level (optional)
- WAF integration for additional security (optional)

### 3. VPC Configuration (Optional)

For enhanced security, deploy the Lambda function in a VPC:

```yaml
VpcConfig:
  SecurityGroupIds:
    - sg-12345678
  SubnetIds:
    - subnet-12345678
    - subnet-87654321
```

## Monitoring and Logging

### 1. CloudWatch Logs

Lambda function logs are automatically sent to CloudWatch. Monitor for:
- Registration attempts and failures
- Authentication events
- Rate limiting violations
- Email delivery status

### 2. CloudWatch Metrics

Set up custom metrics for:
- Registration success/failure rates
- Login success/failure rates
- Email verification rates
- Rate limiting hits

### 3. Alarms

Create CloudWatch alarms for:
- High error rates
- Unusual registration patterns
- Email delivery failures
- DynamoDB throttling

## Troubleshooting

### Common Issues

1. **Email not received**
   - Check SES email verification status
   - Verify FROM_EMAIL environment variable
   - Check CloudWatch logs for SES errors
   - Ensure SES is not in sandbox mode for production

2. **DynamoDB errors**
   - Verify table names match the code
   - Check IAM permissions
   - Monitor for throttling issues

3. **Rate limiting not working**
   - Check DynamoDB RateLimits table
   - Verify TTL configuration
   - Check IP address extraction logic

4. **Authentication failures**
   - Verify password hashing implementation
   - Check user account status (active, verified)
   - Monitor for account lockouts

### Debug Commands

```bash
# Check Lambda function logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/

# Get recent log events
aws logs filter-log-events \
  --log-group-name /aws/lambda/your-function-name \
  --start-time $(date -d '1 hour ago' +%s)000

# Check DynamoDB table status
aws dynamodb describe-table --table-name Users
aws dynamodb describe-table --table-name RateLimits

# Test SES configuration
aws ses get-send-quota
aws ses get-send-statistics
```

## Performance Optimization

### 1. Lambda Configuration

- **Memory**: Start with 512MB, adjust based on performance
- **Timeout**: Set to 30 seconds for email operations
- **Concurrency**: Configure reserved concurrency if needed

### 2. DynamoDB Optimization

- **Indexes**: Use GSI efficiently for email and token lookups
- **Capacity**: Monitor and adjust if using provisioned capacity
- **Caching**: Consider DynamoDB Accelerator (DAX) for high-traffic scenarios

### 3. Email Optimization

- **Templates**: Use SES templates for better performance
- **Batching**: Implement email queuing for high volumes
- **Delivery**: Monitor bounce and complaint rates

## Scaling Considerations

### High Traffic Scenarios

1. **Database Scaling**
   - Use DynamoDB on-demand billing
   - Implement read replicas if needed
   - Consider database sharding for very high volumes

2. **Lambda Scaling**
   - Monitor concurrent executions
   - Configure reserved concurrency
   - Consider provisioned concurrency for consistent performance

3. **Email Scaling**
   - Request SES sending limit increases
   - Implement email queuing with SQS
   - Use multiple verified domains for higher limits

### Multi-Region Deployment

For global applications:
- Deploy Lambda functions in multiple regions
- Use DynamoDB Global Tables for data replication
- Configure Route 53 for geographic routing
- Replicate SES configuration across regions

## Maintenance

### Regular Tasks

1. **Monitor logs** for errors and unusual patterns
2. **Review metrics** and adjust rate limits if needed
3. **Update dependencies** and security patches
4. **Clean up expired tokens** (automatic with TTL)
5. **Review and rotate secrets** periodically

### Backup and Recovery

1. **DynamoDB backups** - Enable point-in-time recovery
2. **Code backups** - Use version control and CI/CD
3. **Configuration backups** - Document all settings
4. **Disaster recovery** - Test recovery procedures

## Cost Optimization

### AWS Cost Factors

1. **Lambda**: Execution time and memory usage
2. **DynamoDB**: Read/write capacity and storage
3. **SES**: Email sending volume
4. **API Gateway**: Request volume
5. **CloudWatch**: Log storage and metrics

### Cost Reduction Strategies

1. **Optimize Lambda memory** allocation
2. **Use DynamoDB on-demand** for variable workloads
3. **Implement efficient caching** to reduce database calls
4. **Monitor and clean up** unused resources
5. **Use AWS Cost Explorer** to track spending