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
- dgrijalva/jwt-go v3.2.0 - Declared dependency; JWT authentication is not implemented
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

## Mobile Authentication

Reviewed for [MOBL-3269](https://atlassian-wcsd.atlassian.net/browse/MOBL-3269).
Related requirements: [Mobile App Authentication Requirements](https://atlassian-wcsd.atlassian.net/wiki/spaces/MD/pages/10059818)
and [MOBL-2143 — Key mobile authentication](https://atlassian-wcsd.atlassian.net/browse/MOBL-2143).
The following distinguishes behavior verified in this repository from requirements
that still need implementation. The linked requirements page and ADR 004 are not
included in this repository and have not been verified here.

### Current Architecture and Behavior

```text
Caller → API Gateway (GET /bootstrap) → SubmitImage Lambda → S3 / DynamoDB
         No authorizer or API-key requirement configured in template.yml
```

- [template.yml](template.yml) exposes `GET /bootstrap`, accepting an image URL
  in the `url` query parameter. The HTTPS endpoint is available in the
  `SubmitImageAPI` stack output.
- [lambda.go](submitImage/opendevopslambda/lambda.go) reads the URL, checks its
  file extension, downloads the image, stores it in S3, and records its ID in
  DynamoDB. It does not inspect authorization headers, validate API keys or JWTs,
  or authenticate a mobile user. Treat this route as unauthenticated in the
  repository configuration; do not rely on it to protect user data.
- AWS execution-role policies allow the Lambda to access AWS services. They do
  not authenticate callers or authorize individual users.
- [go.mod](submitImage/go.mod) declares `dgrijalva/jwt-go`, but the handler does
  not use it. Sending an `Authorization` or `x-api-key` header does not enable
  authentication in this implementation.
- [SignatureCanvas.tsx](src/components/SignatureCanvas.tsx) uses the placeholder
  `current-user-id`. [SignatureService.ts](src/services/SignatureService.ts)
  stores signatures in memory and filters by a supplied `userId`; this is not an
  authorization boundary. Handwritten signatures are not authentication keys.
- The handler defines a `200` response after processing and `500` responses for
  missing URLs, URL decoding failures, and unsupported extensions. It also
  returns Go errors, which can affect the response delivered by API Gateway.
  It defines no authentication-specific `401` or `403` response.
- [api.yaml](api.yaml) is a sample pets API, not the deployed `/bootstrap`
  contract; do not use it as an authentication specification.

### Planned Key Authentication (MOBL-2143)

The parent issue proposes changes to `AppleLoginButton.tsx`, `AppleAuthService.ts`,
and `AppleUser.ts`, plus new `KeyAuthenticationService.ts`,
`KeyAuthenticationTypes.ts`, and `KeyStorageService.ts` files. None of these files
exist in this checkout. Apple login, key registration and validation, token
issuance/refresh/revocation, and secure key storage are not implemented here.
Implementing them is separate from this documentation review.

### Developer Implementation Requirements

Before integrating mobile authentication, agree on the server contract and
implement server-side enforcement; adding client headers alone is insufficient.

- **Credentials:** Define key enrollment, proof of possession, rotation, and
  revocation. Store private keys and tokens using the mobile platform's secure
  storage, not source code or ordinary application storage. Never send private
  keys to the server or log credentials.
- **API keys and JWTs:** Specify supported headers and credential issuance.
  API keys identifying an application must not be treated as user identity.
  If JWTs are adopted, validate their signature with an explicitly allowed
  algorithm, issuer, audience, and expiry on the server. Do not ship shared
  signing secrets in the mobile app.
- **Authorization:** Derive user identity from verified credentials, not the
  client-supplied `userId`. Enforce permissions and resource ownership on the
  server for every protected operation.
- **Security policy:** Use HTTPS. Confirm encryption, rate limiting, and 2FA
  requirements with the linked requirements page and ADR 004 before implementation.
  This checkout does not define the reported 14 permissions, Standard/Premium/
  Enterprise transaction limits or retry policies, AES-256-GCM/SHA-256 policy,
  application authentication rate limits, or 2FA enforcement. Do not assume
  these controls are present or invent their values.
- **User feedback:** Define a stable error contract: `401` for missing or invalid
  credentials and `403` for authenticated callers without permission. Show clear
  success/failure feedback without exposing credential details. These are
  intended responses, not current handler behavior.
- **Validation:** When authentication is implemented, add tests for missing,
  invalid, expired, and revoked credentials, wrong JWT issuer/audience/algorithm,
  denied permissions, cross-user access, and compatibility with existing login.
  The existing [handler test](submitImage/opendevopslambda/lambda_test.go) covers
  an unauthenticated successful request only; it does not establish auth coverage.
