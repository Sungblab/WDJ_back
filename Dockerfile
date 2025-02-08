# Node.js 공식 이미지를 기반으로 함
FROM node:18-alpine

# 작업 디렉토리 생성
WORKDIR /usr/src/app

# package.json과 package-lock.json 복사
COPY package*.json ./

# 의존성 설치
RUN npm install --production

# 소스 코드 복사
COPY . .

# uploads 디렉토리 생성
RUN mkdir -p uploads && chmod 777 uploads

# 포트 설정
EXPOSE 3000

# 애플리케이션 실행
CMD ["node", "server.js"] 