const express = require("express");

const routes = require("./routes/index");

const morgan = require("morgan"); // HTTP request logger middleware for node.js

const rateLimit = require("express-rate-limit");

const helmet = require("helmet"); // 

const mongoSanitize = require("express-mongo-sanitize"); //

// commenting below from gpt
//const bodyParser = require("body-parser");

const xssClean = require("xss-clean");

const cors = require("cors");


const app = express();

// adding this to next comment indicator from gpt
app.use((req, res, next) => {
    console.log(`Incoming request: ${req.method} ${req.url}`);
    console.log(`Content-Length: ${req.headers["content-length"] || "unknown"} bytes`);
    next();
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
//

// commenting out from GPT
// app.use(express.urlencoded({
//     extended: true
// }));

app.use(mongoSanitize());

app.use(xssClean());

app.use(cors({
    origin: "*",
    methods: ["GET", "PATCH", "POST", "DELETE", "PUT"],
    credentials: true
}));





//commenting 2 lines below from gpt
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({extended: true}));

app.use(helmet());

if(process.env.NODE_ENV === "development"){
    app.use(morgan("dev"));
}

const limiter = rateLimit({
    max: 3000,
    windowMs: 60 * 60 * 1000, // one hour
    message: "Too many requests from this IP, Please try again in one hour"
})

app.use("/tawk", limiter);

app.use(routes);


module.exports = app;

