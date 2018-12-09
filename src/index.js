const cookieParser = require("cookie-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config({ path: ".env" });
const createServer = require("./createServer");
const db = require("./db");

const server = createServer();

server.express.use(cookieParser());

// server.express.use(
//   cors({
//     credentials: true,
//     origin: process.env.FRONTEND_URL
//   })
// );

server.express.use((req, res, next) => {
  const { token } = req.cookies;
  console.log("token", token);
  if (token) {
    const { userId } = jwt.verify(token, process.env.APP_SECRET);
    req.userId = userId;
  }
  next();
});

server.express.use(async (req, res, next) => {
  if (!req.userId) return next();
  const user = await db.query.user(
    { where: { id: req.userId } },
    `{ id, name, email, permission }`
  );
  req.user = user;
  next();
});

const options = {
  port: process.env.PORT,
  endpoint: "/graphql",
  playground: "/playground",
  cors: {
    credentials: true,
    origin: process.env.FRONTEND_URL
  }
};
server.start(options, ({ port }) =>
  console.log(
    `Server started, listening on port ${port} for incoming requests.`
  )
);
