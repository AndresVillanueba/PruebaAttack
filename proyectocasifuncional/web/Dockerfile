FROM node:18-alpine
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev       # o  npm install --omit=dev --production

COPY . .

ENV PORT=8080
EXPOSE 8080
CMD ["npm", "start"]

