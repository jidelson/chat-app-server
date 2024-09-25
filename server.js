const app = require("./app");

process.on("uncaughtException", (err) => {
    console.log(err);
    process.exit(1);
});

const http = require("http"); // this comes from node.js

const server = http.createServer(app);

// port # defined in config.env
const port = process.env.PORT || 8000;

server.listen(port, () => {
    console.log(`App running on port ${port}`)
});

process.on("unhandledRejection", (err) => {
    console.log(err);
    server.close(() => {
        process.exit(1);
    });
});