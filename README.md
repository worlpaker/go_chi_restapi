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
git clone https://github.com/worlpaker/go_chi_restapi.git
```

- Make sure you are in the correct directory:

```bash
cd go_chi_restapi
```

- Before starting the services, ensure that you set the necessary environment variables in both the `config/config.go` and the `docker-compose.yml`.

- Build containers and start services:

```bash
docker-compose up --build -d
```

## Access

Backend: <http://localhost:8000/>

## API Endpoints

Information about each endpoint, including request/response formats and parameters, is available in the Swagger API documentation.

- Access Docs on API: <http://localhost:8000/swagger/>

- Alternatively, you can also access it manually at: `api/docs`

## Running Tests

- Run tests using the `make` command:

```sh
make test
```

- To generate coverage reports and obtain more detailed information about the tests, use the following `make` command:

```sh
make cover
```
