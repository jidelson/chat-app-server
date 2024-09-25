const jwt = require("jsonwebtoken");

//
const User = require("../models/user");

const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

// Register New User
exports.register = async(req, res, next) => {
    const {firstName, lastName, email, password} = req.body;

    

    // check if a verified user with given email exists

    const existing_user = await User.findOne({email: email});

    if(existing_user && existing_user.verified){
        res.status(400).json({
            status: "error",
            message: "Email is already in use, please login."
        })
    }
    else if(existing_user){
        await User.findOneAndUpdate({email: email}, {}, );
    }
    else{

    }


}


exports.login = async (req, res, next) => {
  //

  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({
      status: "error",
      message: "Both email and password are required",
    });
  }

  const userDoc = await User.findOne({ email: email }).select("+password");

  if (!userDoc || (await userDoc.correctPassword(password, userDoc.password))) {
    res.status(400).json({
      status: "error",
      message: "Email or password are incorrect",
    });
  }

  const token = signToken(userDoc._id);

  res.status(200).json({
    status: "success",
    message: "Logged in successfully",
    token,
  });
};
