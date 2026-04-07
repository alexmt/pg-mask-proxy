# pg-mask-proxy

A lightweight PostgreSQL proxy that masks sensitive column values in query results. Sits between your client and a PostgreSQL backend, intercepting `SELECT` responses and replacing configured column values with `****`.

Useful for giving AI coding assistants (e.g. Claude Code) or other tools read access to a production database without exposing PII like email addresses or phone numbers.

## How it works

The proxy speaks the PostgreSQL wire protocol. It forwards all traffic transparently except for `RowDescription` and `DataRow` messages — where it tracks column names and rewrites values for any column matching the configured mask list.

It also handles:
- SSL/TLS upgrade to the backend (required for RDS Proxy)
- Declining `SSLRequest` / `GSSENCRequest` from clients so plain connections work
- Stripping `SCRAM-SHA-256-PLUS` from auth offers so clients without TLS can authenticate

## Installation

```bash
brew install alexmt/tap/pg-mask-proxy
```

## Usage

```bash
BACKEND_ADDR=mydb.proxy.rds.amazonaws.com:5432 \
BACKEND_SSL=true \
MASK_COLUMNS=email,phone \
pg-mask-proxy
```

Then connect your client to `localhost:20000` as if it were the real database.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `BACKEND_ADDR` | *(required)* | Backend PostgreSQL address (`host:port`) |
| `BACKEND_SSL` | `false` | Connect to backend with TLS (required for RDS Proxy) |
| `MASK_COLUMNS` | `email` | Comma-separated list of column names to mask |
| `LISTEN_ADDR` | `:20000` | Local address to listen on |
| `DEBUG` | `false` | Print debug logs to stderr |

## Example

```bash
# Start the proxy
BACKEND_ADDR=prod-db.proxy.rds.amazonaws.com:5432 \
BACKEND_SSL=true \
MASK_COLUMNS=email,ssn,phone \
pg-mask-proxy

# Connect with psql (in another terminal)
psql "host=localhost port=20000 dbname=mydb user=myuser sslmode=disable"
```

```
mydb=> SELECT id, name, email FROM users LIMIT 3;
 id |    name     | email
----+-------------+-------
  1 | Alice Smith | ****
  2 | Bob Jones   | ****
  3 | Carol White | ****
```

## Building from source

```bash
make build   # output: dist/pg-mask-proxy
make lint    # requires golangci-lint
```
