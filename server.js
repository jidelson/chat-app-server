const app = require("./app");

const http = require("http"); // this comes from node.js

const server = http.createServer(app);

// port # defined in config.env
const port = process.env.PORT || 8000;

server.listen(port, () => {
    console.log(`App running on port ${port}`)
});