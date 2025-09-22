# Infrastructure Metrics Feature

This document describes the infrastructure performance metrics feature that has been added to the service health overview page.

## Overview

The infrastructure metrics feature provides real-time monitoring of key performance indicators including:

- **CPU Usage** - Processor utilization, core count, and load averages
- **Memory Usage** - RAM utilization, total/used/available memory
- **I/O Performance** - Disk usage, read/write throughput, and IOPS
- **Network Throughput** - Inbound/outbound traffic, connections, and packet rates

## Features

### ✅ Real-time Metrics Display
- Auto-refreshing metrics with configurable intervals
- Visual progress bars and status indicators
- Color-coded alerts based on threshold values

### ✅ Comprehensive Service Health Overview
- Overall service status monitoring
- Active alerts and notifications
- Service uptime tracking

### ✅ User Feedback System
- Built-in feedback mechanism for users
- Rating system and categorized comments
- Helps improve monitoring capabilities

### ✅ Responsive Design
- Mobile-friendly interface
- Accessible design patterns
- Professional styling with hover effects

### ✅ Error Handling
- Graceful degradation when API is unavailable
- Loading states and error messages
- Retry functionality

## File Structure

```
src/
├── types/
│   └── InfrastructureMetrics.ts          # TypeScript type definitions
├── services/
│   └── InfrastructureMetricsService.ts   # API service for fetching metrics
├── components/
│   └── InfrastructureMetrics/
│       ├── InfrastructureMetricsPanel.tsx    # Main metrics display component
│       └── InfrastructureMetrics.styles.ts   # Styling definitions
├── pages/
│   └── ServiceHealthOverview.tsx         # Main service health page
└── examples/
    └── ServiceHealthExample.tsx          # Usage examples
```

## Usage

### Basic Usage

```tsx
import ServiceHealthOverview from './pages/ServiceHealthOverview';

function App() {
  return (
    <ServiceHealthOverview
      serviceName="My Application"
      autoRefresh={true}
      refreshInterval={30000}
    />
  );
}
```

### Standalone Metrics Panel

```tsx
import InfrastructureMetricsPanel from './components/InfrastructureMetrics/InfrastructureMetricsPanel';

function Dashboard() {
  return (
    <InfrastructureMetricsPanel
      autoRefresh={true}
      refreshInterval={15000}
      showFeedback={true}
    />
  );
}
```

## API Requirements

The infrastructure metrics feature expects the following API endpoints:

### Required Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/metrics/current` | GET | Current infrastructure metrics |
| `/api/metrics/overview` | GET | Comprehensive metrics with history and alerts |
| `/api/metrics/health` | GET | Service health check |

### Optional Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/metrics/history` | GET | Historical metrics data |
| `/api/metrics/alerts` | GET | Active alerts |
| `/api/metrics/feedback` | POST | Submit user feedback |
| `/api/metrics/config` | GET | Metrics configuration |

### Example API Response

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "cpu": {
    "usage": 45.2,
    "cores": 4,
    "loadAverage": {
      "oneMinute": 1.2,
      "fiveMinutes": 1.1,
      "fifteenMinutes": 0.9
    }
  },
  "memory": {
    "usage": 68.5,
    "total": 8192,
    "used": 5611,
    "available": 2581,
    "cached": 1024
  },
  "io": {
    "readThroughput": 25.4,
    "writeThroughput": 12.8,
    "readIOPS": 150,
    "writeIOPS": 75,
    "diskUsage": 72.3
  },
  "network": {
    "inboundThroughput": 15.2,
    "outboundThroughput": 8.7,
    "packetsPerSecond": 1250,
    "connectionsActive": 45,
    "connectionsTotal": 128
  },
  "serviceStatus": "healthy",
  "uptime": 86400
}
```

## Configuration

### Environment Variables

Set the following environment variable to configure the metrics API endpoint:

```bash
REACT_APP_METRICS_API_URL=https://api.yourservice.com/metrics
```

### Component Props

#### ServiceHealthOverview Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `serviceName` | string | "Signature Application" | Name of the service |
| `autoRefresh` | boolean | true | Enable automatic refresh |
| `refreshInterval` | number | 30000 | Refresh interval in milliseconds |
| `className` | string | "" | Additional CSS class |

#### InfrastructureMetricsPanel Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `autoRefresh` | boolean | true | Enable automatic refresh |
| `refreshInterval` | number | 30000 | Refresh interval in milliseconds |
| `showFeedback` | boolean | true | Show feedback section |
| `className` | string | "" | Additional CSS class |

## Customization

### Styling

The components use comprehensive built-in styling, but you can customize the appearance by:

1. **Modifying the styles file**: Edit `src/components/InfrastructureMetrics/InfrastructureMetrics.styles.ts`
2. **Adding custom CSS classes**: Use the `className` prop to add your own styles
3. **Overriding CSS variables**: Define custom CSS variables for colors and spacing

### Thresholds

Alert thresholds can be configured through the API configuration endpoint or by modifying the default values in the service:

```typescript
// Default thresholds
alertThresholds: {
  cpu: 80,      // 80% CPU usage
  memory: 85,   // 85% memory usage
  io: 90,       // 90% disk usage
  network: 95   // 95% network utilization
}
```

## Accessibility

The infrastructure metrics feature includes:

- **Semantic HTML** - Proper heading structure and landmarks
- **ARIA labels** - Screen reader friendly labels
- **Keyboard navigation** - Full keyboard accessibility
- **Color contrast** - WCAG compliant color schemes
- **Focus indicators** - Clear focus states for interactive elements

## Performance Considerations

- **Efficient rendering** - Components use React hooks for optimal performance
- **Configurable refresh rates** - Adjust based on your monitoring needs
- **Error boundaries** - Prevent crashes from affecting the entire application
- **Lazy loading** - Components can be code-split for better initial load times

## Browser Support

The infrastructure metrics feature supports:

- Chrome 70+
- Firefox 65+
- Safari 12+
- Edge 79+

## Troubleshooting

### Common Issues

1. **Metrics not loading**
   - Check the API endpoint configuration
   - Verify network connectivity
   - Check browser console for errors

2. **Auto-refresh not working**
   - Ensure `autoRefresh` prop is set to `true`
   - Check if the component is properly mounted
   - Verify the refresh interval is reasonable (> 1000ms)

3. **Styling issues**
   - Check for CSS conflicts
   - Verify the styles are properly imported
   - Use browser dev tools to inspect elements

### Debug Mode

Enable debug logging by setting:

```javascript
localStorage.setItem('debug', 'metrics:*');
```

## Contributing

When contributing to the infrastructure metrics feature:

1. Follow the existing code patterns and TypeScript types
2. Add proper error handling for new functionality
3. Include comprehensive JSDoc comments
4. Test with different screen sizes and browsers
5. Update this README for any new features or changes

## License

This feature is part of the signature application and follows the same licensing terms.