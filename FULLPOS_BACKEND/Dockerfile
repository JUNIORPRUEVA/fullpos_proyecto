FROM node:18-bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y openssl libxml2-utils \
  && rm -rf /var/lib/apt/lists/*

RUN openssl version
RUN xmllint --version

COPY package*.json ./
RUN npm ci

COPY prisma ./prisma
RUN npx prisma generate

COPY tsconfig.json ./
COPY src ./src
COPY resources ./resources

RUN npm run build

EXPOSE 4000

CMD ["npm", "run", "start:runtime"]
