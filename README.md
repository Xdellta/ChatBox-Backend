# ChatBox BACKEND

ChatBox is a web-based social media chat application built with Vue.js (**[frontend](https://github.com/Xdellta/ChatBox-Frontend.git)**) and Express.js (**[backend](https://github.com/Xdellta/ChatBox-Backend.git)**). The project is educational in nature and demonstrates the use of WebSocket to handle real-time communication between client and server. In addition, the application includes a REST API implementation in Express.js and general support for Vue.js features. ChatBox features a futuristic UI/UX interface, combining modern design with smooth user interaction.

<br>

### 🛠️ Tools and Technologies
![Vue.js](https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D)
![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
![HTML](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![Express](https://img.shields.io/badge/Express%20js-000000?style=for-the-badge&logo=express&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Prisma](https://img.shields.io/badge/Prisma-3982CE?style=for-the-badge&logo=Prisma&logoColor=white)
![Postgresql](https://img.shields.io/badge/postgresql-4169e1?style=for-the-badge&logo=postgresql&logoColor=white)

<br>

### 📜 License
[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE) By [Patryk Piotrowski](https://github.com/Xdellta)

<br>

## 🔌 Endpoint Specification

### 1. Login
- **URL:** `/api/auth/login`
- **Method:** `POST`
- **Description:** Logs in a user and returns access and refresh tokens.
- **Request:**
```sh
{
  "email": "user@example.com",
  "password": "Password!123"
}
```
- **Response:**
  - **200:** Success message with tokens in headers.
  - **400:** Invalid email/password.
  - **500:** Server error.

<br>

### 2. Register
- **URL:** `/api/auth/register`
- **Method:** `POST`
- **Description:** Registers a new user and returns access and refresh tokens.
- **Request:**
```sh
{
  "username": "user123",
  "email": "user@example.com",
  "password": "Password!123"
}
```
- **Response:**
  - **200:** Success message with tokens in headers.
  - **400:** Invalid input (`username`, `email`, `password`) or user already exists.
  - **500:** Server error.

<br>

## 🚀 Getting Started
For proper operation, you must also download: **[ChatBox FRONTEND](https://github.com/Xdellta/ChatBox-Frontend.git)**

<br>

**1.** Clone the repository:
```sh
git clone https://github.com/Xdellta/ChatBox-Backend.git
```
```sh
cd ChatBox-Backend
```

<br>

**2.** Copy the `.env.example` file to `.env`, and then configure the contents:
```sh
cp .env.example .env
```

<br>

**3.** Install dependencies:
```sh
npm install
```

<br>

**4.** Initialize Prisma and apply migrations:
```sh
npx prisma init
```
```sh
npx prisma migrate dev --name init
```

<br>

**5.** (Optional) Seed the database with initial data:
```sh
npm run seed
```

<br>

**6.** Run the application in `development` or `production`:
```sh
npm run dev
```
```sh
npm run start
```