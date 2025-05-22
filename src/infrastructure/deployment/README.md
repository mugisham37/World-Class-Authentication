# World-Class-Authentication Server Deployment

This directory contains configuration files and deployment scripts for running the World-Class-Authentication system with various web servers and load balancers.

## Available Server Technologies

The following server technologies are configured and ready to use:

1. **Nginx** - Lightning-fast reverse proxy and load balancer
2. **Apache HTTP Server** - Robust and feature-rich web server
3. **Caddy** - Modern web server with automatic HTTPS
4. **HAProxy** - Enterprise-grade load balancer for high availability

## Directory Structure

- `servers/` - Contains configuration files for each server technology
- `docker-compose.proxy.yml` - Docker Compose file for running all server technologies

## Getting Started

### Prerequisites

- Docker and Docker Compose installed
- SSL certificates (or use Let's Encrypt with the included Certbot service)

### Setup

1. Create required directories:

```bash
mkdir -p ssl www logs/{nginx,apache,caddy,haproxy} caddy_data caddy_config
```

2. Update domain names in configuration files:

Replace `auth.yourdomain.com` with your actual domain name in:

- `servers/nginx.conf`
- `servers/apache.conf`
- `servers/Caddyfile`
- `servers/haproxy.cfg`

3. SSL Certificates:

For production, you'll need SSL certificates. You can:

- Use Let's Encrypt with the included Certbot service
- Provide your own certificates in the `ssl` directory

### Running the Services

#### Using All Server Technologies (Testing)

This setup runs all server technologies simultaneously on different ports:

```bash
docker-compose -f docker-compose.proxy.yml up -d
```

Access the services at:

- Nginx: http://localhost:80 and https://localhost:443
- Apache: http://localhost:8080 and https://localhost:8443
- Caddy: http://localhost:9080 and https://localhost:9443
- HAProxy: http://localhost:10080 and https://localhost:10443
- HAProxy Stats: http://localhost:8404/stats

#### Using a Specific Server Technology (Production)

For production, you'll typically use just one server technology. Edit the `docker-compose.proxy.yml` file to comment out the services you don't need.

Example for using only Nginx:

```yaml
version: '3.8'

services:
  app:
    # ... app configuration ...

  nginx:
    # ... nginx configuration ...

  db:
    # ... db configuration ...

  redis:
    # ... redis configuration ...

  certbot:
    # ... certbot configuration ...

volumes:
  postgres_data:
  redis_data:

networks:
  auth-network:
    driver: bridge
```

Then run:

```bash
docker-compose -f docker-compose.proxy.yml up -d
```

## Server Technology Comparison

### Nginx

- **Strengths**: Extremely fast, low memory footprint, excellent for static content
- **Best for**: High-traffic websites, static content serving, microservices
- **Configuration**: `servers/nginx.conf`

### Apache HTTP Server

- **Strengths**: Feature-rich, extensive module ecosystem, .htaccess support
- **Best for**: Shared hosting environments, complex configurations
- **Configuration**: `servers/apache.conf`

### Caddy

- **Strengths**: Automatic HTTPS, simple configuration, modern features
- **Best for**: Quick deployments, modern applications, ease of use
- **Configuration**: `servers/Caddyfile`

### HAProxy

- **Strengths**: Advanced load balancing, high availability, detailed metrics
- **Best for**: Enterprise applications, high-availability clusters, complex routing
- **Configuration**: `servers/haproxy.cfg`

## Horizontal Scaling

For horizontal scaling, you can:

1. Uncomment the `deploy` section in the `app` service in `docker-compose.proxy.yml`:

```yaml
deploy:
  replicas: 3
```

2. Uncomment the additional backend servers in the server configuration files:

- In `nginx.conf`:

```
server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
server 127.0.0.1:3002 max_fails=3 fail_timeout=30s;
```

- In `apache.conf`:

```
BalancerMember "http://127.0.0.1:3001" route=node2 connectiontimeout=1 retry=30 timeout=60
BalancerMember "http://127.0.0.1:3002" route=node3 connectiontimeout=1 retry=30 timeout=60
```

- In `Caddyfile`:

```
to localhost:3001
to localhost:3002
```

- In `haproxy.cfg`:

```
server auth2 127.0.0.1:3001 check inter 5s rise 2 fall 3 weight 100 maxconn 500
server auth3 127.0.0.1:3002 check inter 5s rise 2 fall 3 weight 100 maxconn 500
```

## Performance Tuning

Each server configuration includes performance optimizations, but you may need to adjust them based on your specific hardware and traffic patterns:

- **Nginx**: Adjust `worker_processes`, `worker_connections`, and buffer sizes
- **Apache**: Adjust `StartServers`, `MinSpareServers`, `MaxSpareServers`, and `MaxRequestWorkers`
- **Caddy**: Adjust the number of workers via environment variables
- **HAProxy**: Adjust `maxconn`, `nbthread`, and timeout values

## Security Considerations

All server configurations include:

- HTTP to HTTPS redirection
- Modern TLS configurations (TLS 1.2+)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Rate limiting for API endpoints
- Disabled server tokens/signatures

## Monitoring

- **HAProxy**: Access the stats page at http://localhost:8404/stats
- **Nginx**: Access logs at `logs/nginx/`
- **Apache**: Access logs at `logs/apache/`
- **Caddy**: Access logs at `logs/caddy/`

## Troubleshooting

### Common Issues

1. **SSL Certificate Issues**:

   - Ensure certificates exist in the correct location
   - Check certificate permissions
   - Verify domain names match configuration

2. **Connection Refused**:

   - Check if the backend application is running
   - Verify network settings and port mappings
   - Check firewall rules

3. **Performance Issues**:
   - Monitor resource usage (CPU, memory)
   - Adjust worker/thread settings
   - Consider horizontal scaling

### Logs

Check the logs for each service:

```bash
docker-compose -f docker-compose.proxy.yml logs nginx
docker-compose -f docker-compose.proxy.yml logs apache
docker-compose -f docker-compose.proxy.yml logs caddy
docker-compose -f docker-compose.proxy.yml logs haproxy
docker-compose -f docker-compose.proxy.yml logs app
```
