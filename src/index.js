const cookieParser = require("cookie-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config({ path: "variables.env" });
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
  if (token) {
    const { userId } = jwt.verify(token, process.env.APP_SECRET);
    req.userId = userId;
  }
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
