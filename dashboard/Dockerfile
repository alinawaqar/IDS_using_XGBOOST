# Stage 1: Build React Dashboard
FROM --platform=linux/amd64 node:18-alpine AS build
WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Serve with Nginx Proxy
FROM --platform=linux/amd64 nginx:alpine
# Copy build output (checks both Vite 'dist' and Create-React-App 'build' paths)
COPY --from=build /app/dist /usr/share/nginx/html

# Replace default Nginx configuration with custom proxy setup
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]