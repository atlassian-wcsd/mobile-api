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

## API Documentation

This section provides comprehensive documentation for the Mobile Dev API. The API follows the OpenAPI 3.0 specification.

### Base URL

```
https://api.yourapp.com/v1
```

### Authentication

The API uses JWT (JSON Web Token) authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

---

### Endpoints

#### Pets

##### List All Pets

Retrieve a paginated list of all pets.

**Endpoint:** `GET /pets`

**Parameters:**

| Name  | In    | Type    | Required | Description                              |
|-------|-------|---------|----------|------------------------------------------|
| limit | query | integer | No       | How many items to return at one time (max 100) |

**Response:**

- **200 OK** - A paged array of pets

  **Headers:**
  | Name   | Type   | Description                          |
  |--------|--------|--------------------------------------|
  | x-next | string | A link to the next page of responses |

  **Body:**
  ```json
  [
    {
      "id": 1,
      "name": "Fluffy",
      "tag": "cat"
    },
    {
      "id": 2,
      "name": "Buddy",
      "tag": "dog"
    }
  ]
  ```

- **Default** - Unexpected error
  ```json
  {
    "code": 500,
    "message": "Internal server error"
  }
  ```

**Example Request:**

```bash
curl -X GET "https://api.yourapp.com/v1/pets?limit=10" \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json"
```

---

##### Create a Pet

Create a new pet entry.

**Endpoint:** `POST /pets`

**Request Body:**

| Field | Type    | Required | Description         |
|-------|---------|----------|---------------------|
| id    | integer | Yes      | Unique identifier   |
| name  | string  | Yes      | Name of the pet     |
| tag   | string  | No       | Category/tag for pet |

**Example Request Body:**
```json
{
  "id": 3,
  "name": "Max",
  "tag": "dog"
}
```

**Response:**

- **201 Created** - Pet successfully created (null response)

- **Default** - Unexpected error
  ```json
  {
    "code": 400,
    "message": "Invalid request body"
  }
  ```

**Example Request:**

```bash
curl -X POST "https://api.yourapp.com/v1/pets" \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": 3,
    "name": "Max",
    "tag": "dog"
  }'
```

---

##### Get Pet by ID

Retrieve information for a specific pet.

**Endpoint:** `GET /pets/{petId}`

**Parameters:**

| Name     | In   | Type   | Required | Description                    |
|----------|------|--------|----------|--------------------------------|
| petId    | path | string | Yes      | The ID of the pet to retrieve  |
| petAlias | path | string | No       | The alias of the pet to retrieve |

**Response:**

- **200 OK** - Expected response to a valid request
  ```json
  {
    "id": 1,
    "name": "Fluffy",
    "tag": "cat"
  }
  ```

- **Default** - Unexpected error
  ```json
  {
    "code": 404,
    "message": "Pet not found"
  }
  ```

**Example Request:**

```bash
curl -X GET "https://api.yourapp.com/v1/pets/1" \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json"
```

---

### Data Models

#### Pet

Represents a pet entity.

| Field | Type    | Required | Description              |
|-------|---------|----------|--------------------------|
| id    | integer | Yes      | Unique identifier (int64) |
| name  | string  | Yes      | Name of the pet          |
| tag   | string  | No       | Category/tag for the pet |

**Example:**
```json
{
  "id": 1,
  "name": "Fluffy",
  "tag": "cat"
}
```

#### Pets

An array of Pet objects (maximum 100 items).

**Example:**
```json
[
  {
    "id": 1,
    "name": "Fluffy",
    "tag": "cat"
  },
  {
    "id": 2,
    "name": "Buddy",
    "tag": "dog"
  }
]
```

#### Error

Represents an error response.

| Field   | Type    | Required | Description           |
|---------|---------|----------|-----------------------|
| code    | integer | Yes      | Error code (int32)    |
| message | string  | Yes      | Error message details |

**Example:**
```json
{
  "code": 404,
  "message": "Pet not found"
}
```

---

### Error Handling

The API uses standard HTTP status codes to indicate the success or failure of requests:

| Status Code | Description                                        |
|-------------|----------------------------------------------------|
| 200         | OK - Request succeeded                             |
| 201         | Created - Resource successfully created            |
| 400         | Bad Request - Invalid request parameters or body   |
| 401         | Unauthorized - Missing or invalid authentication   |
| 404         | Not Found - Resource does not exist                |
| 500         | Internal Server Error - Server-side error          |

### Rate Limiting

API requests may be subject to rate limiting. If you exceed the rate limit, you will receive a `429 Too Many Requests` response. Please implement appropriate retry logic with exponential backoff.

### OpenAPI Specification

The complete OpenAPI 3.0 specification is available in the `api.yaml` file at the root of this repository. You can use tools like [Swagger UI](https://swagger.io/tools/swagger-ui/) or [Redoc](https://redocly.com/redoc/) to visualize and interact with the API documentation.
