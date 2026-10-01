FROM node:22-alpine
WORKDIR /app
COPY src/server/remote/ws.js src/server/remote/frames.js src/server/remote/token.js ./src/server/remote/
COPY relay/ ./relay/
ENV NODE_ENV=production PORT=8080 RELAY_DATA=/app/data
LABEL org.opencontainers.image.revision="v1.16.0"
LABEL org.opencontainers.image.title="IRNetFree relay" org.opencontainers.image.source="https://github.com/sadrazkh/Irnetfree_xray-client"
RUN mkdir -p /app/data && chown -R node:node /app
EXPOSE 8080
USER node
CMD ["node", "relay/server.js"]
