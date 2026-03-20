# Lunch Order Validation Implementation

## Overview
This implementation fulfills the requirements of **HWIRE-44**: App validates lunch order input for completeness and correctness.

## Features Implemented

### 1. **Input Validation**
- **Required Fields Validation**:
  - Name (minimum 2 characters, maximum 100)
  - Menu Selection (required, maximum 200 characters)
  - Quantity (must be a positive integer, minimum 1, maximum 1000)

- **Optional Fields Validation**:
  - Email (validated format if provided, RFC 5322 compliant, maximum 254 characters)
  - Special Instructions (maximum 1000 characters)
  - Delivery Location (maximum 500 characters)

### 2. **Inline Validation**
- Real-time validation on field blur
- Clear, user-friendly error messages
- Visual indicators for invalid fields (red border)
- Errors clear automatically when user starts typing
- Accessible error messages with ARIA attributes

### 3. **Form Submission Prevention**
- Submit button disabled when there are validation errors
- All required fields validated before submission
- Visual feedback during submission ("Submitting..." state)
- Success/error messages displayed after submission

### 4. **Analytics Tracking**
The following events are tracked using the existing FeedbackService:

- **Form Viewed**: When user opens the lunch order form
- **Validation Errors**: Each time a field fails validation (with field name and error type)
- **Submit Attempted**: When user clicks submit button
- **Submit Validation Failed**: When submission is prevented due to validation errors (includes error count and fields)
- **Submit Success**: When order is successfully submitted (includes order ID)
- **Submit Error**: When server returns an error
- **Form Abandoned**: When user cancels with partially filled form (includes which fields were filled)

### 5. **Error Handling**
- Network errors handled gracefully
- Server validation errors displayed to user
- Unexpected errors tracked for debugging
- User-friendly error messages for all failure scenarios

## Files Created

### Models
- `src/models/LunchOrder.ts` - TypeScript interfaces for lunch orders, validation, and API responses

### Services
- `src/services/LunchOrderService.ts` - Service class handling order submission, validation, and API communication

### Components
- `src/components/LunchOrderForm.tsx` - React component with complete form UI, validation, and analytics

### Tests
- `src/services/__tests__/LunchOrderService.test.ts` - Comprehensive unit tests for validation logic (100+ test cases)
- `src/components/__tests__/LunchOrderForm.test.tsx` - Component tests for UI behavior and user interactions

## Validation Rules Summary

| Field | Required | Min Length | Max Length | Format | Other Rules |
|-------|----------|------------|------------|--------|-------------|
| Name | Yes | 2 | 100 | - | Cannot be only whitespace |
| Email | No | - | 254 | RFC 5322 | Valid email format if provided |
| Menu Selection | Yes | 1 | 200 | - | Cannot be empty |
| Quantity | Yes | - | - | Integer | Must be between 1 and 1000 |
| Special Instructions | No | - | 1000 | - | - |
| Delivery Location | No | - | 500 | - | - |

## Design Decisions

1. **Inline Validation**: Validates fields on blur rather than on every keystroke to avoid annoying users with premature errors
2. **Progressive Disclosure**: Only shows errors after user has interacted with a field
3. **Clear Error Recovery**: Errors disappear when user starts correcting them
4. **Accessibility First**: Proper ARIA attributes, roles, and semantic HTML
5. **Analytics Integration**: Reuses existing FeedbackService for consistent tracking
6. **Comprehensive Testing**: 100+ test cases covering edge cases, validation rules, and user interactions

## Usage Example

```tsx
import { LunchOrderForm } from './components/LunchOrderForm';

function App() {
  const handleSuccess = (orderId: string) => {
    console.log(`Order ${orderId} placed successfully!`);
    // Navigate to confirmation page or show success message
  };

  const handleCancel = () => {
    console.log('User cancelled order');
    // Navigate back or close modal
  };

  return (
    <LunchOrderForm 
      onSuccess={handleSuccess}
      onCancel={handleCancel}
    />
  );
}
```

## Testing

### Unit Tests
```bash
npm test -- --testPathPattern="LunchOrderService"
```

### Component Tests
```bash
npm test -- --testPathPattern="LunchOrderForm"
```

### Test Coverage
- **Validation Logic**: Tests for all validation rules including edge cases
- **Form Behavior**: Tests for user interactions, error display, and form submission
- **Analytics**: Tests verifying all tracking events are fired correctly
- **Error Handling**: Tests for network errors, server errors, and validation errors
- **Accessibility**: Tests for ARIA attributes and semantic HTML

## Analytics Dashboard Queries

To analyze validation errors and user behavior:

```javascript
// Track most common validation errors
SELECT field, COUNT(*) as error_count
FROM metrics
WHERE eventName = 'validation_error'
GROUP BY field
ORDER BY error_count DESC;

// Track form abandonment rate
SELECT 
  COUNT(CASE WHEN eventName = 'order_form_viewed' THEN 1 END) as views,
  COUNT(CASE WHEN eventName = 'order_submit_success' THEN 1 END) as submissions,
  COUNT(CASE WHEN eventName = 'order_form_abandoned' THEN 1 END) as abandonments
FROM metrics;
```

## Next Steps

1. **Backend API**: Implement `/api/lunch-orders` endpoint in Go Lambda
2. **Menu Management**: Add dynamic menu item loading from backend
3. **Order Confirmation**: Add confirmation page showing order details
4. **Order History**: Allow users to view their past orders
5. **Admin Dashboard**: Create interface for organizers to view and manage orders

## Requirements Fulfilled

✅ **Required fields validation** - Name, menu selection, and quantity are required
✅ **Format validation** - Email format validated when provided
✅ **Inline validation** - Real-time validation on field blur
✅ **Clear error messages** - User-friendly messages for each validation error
✅ **Prevent invalid submission** - Submit button disabled when errors exist
✅ **Analytics tracking** - Comprehensive tracking of validation errors and abandoned submissions

## Issue Reference
- **Jira Issue**: [HWIRE-44](https://one-atlas-bbnm.atlassian.net/browse/HWIRE-44)
- **Epic**: [HWIRE-43 - Lunch order app](https://one-atlas-bbnm.atlassian.net/browse/HWIRE-43)
