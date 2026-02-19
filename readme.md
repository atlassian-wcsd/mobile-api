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

The API uses JWT-based authentication. Include a valid JWT token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

### Endpoints

#### Pets

##### List All Pets

Retrieves a paginated list of all pets.

**Request:**
```http
GET /pets
```

**Query Parameters:**

| Parameter | Type    | Required | Description                                      |
|-----------|---------|----------|--------------------------------------------------|
| `limit`   | integer | No       | Number of items to return (max 100)              |

**Response (200 OK):**

Returns a paginated array of pets.

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

**Response Headers:**

| Header   | Description                           |
|----------|---------------------------------------|
| `x-next` | A link to the next page of responses  |

---

##### Create a Pet

Creates a new pet entry.

**Request:**
```http
POST /pets
Content-Type: application/json
```

**Request Body:**

```json
{
  "id": 3,
  "name": "Max",
  "tag": "dog"
}
```

| Field  | Type    | Required | Description           |
|--------|---------|----------|-----------------------|
| `id`   | integer | Yes      | Unique identifier     |
| `name` | string  | Yes      | Name of the pet       |
| `tag`  | string  | No       | Category/tag for pet  |

**Response (201 Created):**

Returns an empty response on successful creation.

---

##### Get Pet by ID

Retrieves details of a specific pet by its ID.

**Request:**
```http
GET /pets/{petId}
```

**Path Parameters:**

| Parameter  | Type   | Required | Description                    |
|------------|--------|----------|--------------------------------|
| `petId`    | string | Yes      | The ID of the pet to retrieve  |
| `petAlias` | string | No       | The alias of the pet           |

**Response (200 OK):**

```json
{
  "id": 1,
  "name": "Fluffy",
  "tag": "cat"
}
```

---

### Data Models

#### Pet

| Field  | Type    | Required | Description           |
|--------|---------|----------|-----------------------|
| `id`   | integer | Yes      | Unique identifier (int64) |
| `name` | string  | Yes      | Name of the pet       |
| `tag`  | string  | No       | Category/tag for pet  |

#### Pets

An array of Pet objects (maximum 100 items).

#### Error

| Field     | Type    | Required | Description          |
|-----------|---------|----------|----------------------|
| `code`    | integer | Yes      | Error code (int32)   |
| `message` | string  | Yes      | Error description    |

---

### Error Handling

All endpoints may return error responses in the following format:

```json
{
  "code": 400,
  "message": "Bad Request - Invalid parameters provided"
}
```

**Common HTTP Status Codes:**

| Status Code | Description                                      |
|-------------|--------------------------------------------------|
| 200         | OK - Request successful                          |
| 201         | Created - Resource created successfully          |
| 400         | Bad Request - Invalid request parameters         |
| 401         | Unauthorized - Missing or invalid authentication |
| 404         | Not Found - Resource not found                   |
| 500         | Internal Server Error - Server-side error        |

---

### Example Usage

#### Using cURL

**List all pets:**
```bash
curl -X GET "https://api.yourapp.com/v1/pets?limit=10" \
  -H "Authorization: Bearer <your_jwt_token>"
```

**Create a new pet:**
```bash
curl -X POST "https://api.yourapp.com/v1/pets" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_jwt_token>" \
  -d '{"id": 1, "name": "Fluffy", "tag": "cat"}'
```

**Get a specific pet:**
```bash
curl -X GET "https://api.yourapp.com/v1/pets/1" \
  -H "Authorization: Bearer <your_jwt_token>"
```

#### Using JavaScript (Axios)

```javascript
import axios from 'axios';

const apiClient = axios.create({
  baseURL: 'https://api.yourapp.com/v1',
  headers: {
    'Authorization': 'Bearer <your_jwt_token>',
    'Content-Type': 'application/json'
  }
});

// List all pets
const listPets = async (limit = 10) => {
  const response = await apiClient.get('/pets', { params: { limit } });
  return response.data;
};

// Create a new pet
const createPet = async (pet) => {
  const response = await apiClient.post('/pets', pet);
  return response.data;
};

// Get a specific pet
const getPet = async (petId) => {
  const response = await apiClient.get(`/pets/${petId}`);
  return response.data;
};
```

---

### Rate Limiting

The API implements rate limiting to ensure fair usage. If you exceed the rate limit, you will receive a `429 Too Many Requests` response. Please implement appropriate retry logic with exponential backoff.

### License

This API is licensed under the MIT License.
