# Signature Application

## Dependencies

### Frontend Dependencies
- React 16.0.1 - Core UI library
- React DOM 16.0.1 - DOM manipulation
- node-forge 0.10.0 - Cryptographic operations
- axios 0.19.2 - HTTP client
- TypeScript 4.x - Type safety and developer experience
- signature_pad 4.x - Signature canvas functionality
- Testing Libraries:
  - @testing-library/react - React component testing
  - @testing-library/jest-dom - DOM testing utilities
  - @testing-library/user-event - User event simulation

### Backend Dependencies (Go)
- aws-lambda-go - AWS Lambda runtime
- aws-sdk-go - AWS SDK for Go
- dgrijalva/jwt-go v3.2.0 - JWT authentication
- google/uuid - UUID generation
- stretchr/testify - Testing utilities
- gorilla/mux - HTTP routing

## Installation

### Frontend
```bash
npm install
```

### Backend
```bash
cd submitImage
go mod download
```
