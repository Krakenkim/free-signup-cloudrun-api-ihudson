FROM node:20-slim
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .   # ✅ index.js만 복사하지 말고 전체 복사 (나중에 파일 추가돼도 안전)

ENV PORT=8080
EXPOSE 8080
CMD ["node", "index.js"]
