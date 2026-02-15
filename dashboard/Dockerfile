FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm config set strict-ssl false && npm install

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev", "--", "--host"]
