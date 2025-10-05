# Use official Caddy base image
FROM caddy:2

# Keep config in the default path
COPY config.json /etc/caddy/config.json
CMD ["caddy","run","--config","/etc/caddy/config.json"]

