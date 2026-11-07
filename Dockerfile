FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY relay.mjs ./
ENV NODE_NO_WARNINGS=1 DATA_DIR=/data PORT=7777
VOLUME /data
EXPOSE 7777
CMD ["node", "relay.mjs"]
