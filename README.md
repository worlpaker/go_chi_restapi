# Go Chi Rest API Example

- Simple Go Chi Rest API Example

- Router: Chi - DB: PostgreSQL - Env: Docker

## Includes

- Swagger Documentation

- User authorization with JWT on the backend

- Go unit tests with SQL mocking

- Many-to-many RDBMS

- Different response messages based on languages (Accept-Language)

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)

## Setup

- Clone the repository:

```bash
git clone https://github.com/worlpaker/go_chi_restapi_example.git
```

- Make sure you are in the correct directory:

```bash
cd go_restapi_example
```

- Set environment variables in config.go before starting the services.

- Build containers and start services:

```bash
docker-compose up --build
```

- Detailed commands: [Docker Commands](https://docs.docker.com/engine/reference/commandline/docker/)

## Access

Backend: <http://localhost:8000>

## API Endpoints

Information about each endpoint, including request/response formats and parameters, is available in the Swagger API documentation.

- Access Docs on API: <http://localhost:8000/swagger/>

- Alternatively, you can also access it manually at: `api/docs`

## Tests

To run the unit tests, execute the following command:

- Run it with make:

```bash
make test
```

- Manually:

```bash
go test -v ./...
```
