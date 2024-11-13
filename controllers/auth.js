const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const mailService = require("../services/mailer");
const crypto = require("crypto");

const filterObj = require("../utils/filterObj");

// Model
const User = require("../models/user");
const otp = require("../Templates/Mail/otp");
const resetPassword = require("../Templates/Mail/resetPassword");
const { promisify } = require("util");
const catchAsync = require("../utils/catchAsync");

const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

// Register New User
exports.register = catchAsync(async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  const filteredBody = filterObj(
    req.body,
    "firstName",
    "lastName",
    "email",
    "password"
  );

  // check if a verified user with given email exists

  const existing_user = await User.findOne({ email: email });

  if (existing_user && existing_user.verified) {

    return res.status(400).json({
      status: "error",
      message: "Email is already in use, please login.",
    });
  } else if (existing_user) {
      await User.findOneAndUpdate({ email: email }, filteredBody, { 
        new: true, 
        validateModifiedOnly: true 
      });

    // generate OTP and send email to user
    req.userId = existing_user._id;
    next();
  } else {
    // if user record is not available in DB
    const new_user = await User.create(filteredBody);

    // generate OTP and send email to user
    req.userId = new_user._id;
    next();
  }
});

exports.sendOTP = catchAsync(async (req, res, next) => {
  const { userId } = req;
  const new_otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    specialChars: false,
    lowerCaseAlphabets: false,
  });

  const otp_expiry_time = Date.now() + 10 * 60 * 1000; // 10 mins after OTP is sent

 const user = await User.findByIdAndUpdate(userId, {
    otp_expiry_time: otp_expiry_time
  });

  user.otp = new_otp.toString();

  await user.save({ new: true, validateModifiedOnly: true });

  // TODO Send Mail

  mailService.sendEmail({
    from: "contact@example.in", // CHANGE THIS EMAIL ADDRESS LATER ALSO IN mailer.js
    to: user.email,
    subject: "Verification OTP",
    html: otp(user.firstName, new_otp),
    // text: `Your OTP is ${new_otp}. This is valid for 10 minutes.`,
    attachments: []
  });

  res.status(200).json({
    status: "success",
    message: "OTP Sent Successfully!",
  });
});

exports.verifyOTP = catchAsync(async (req, res, next) => {
  // verify OTP and update user record accordingly

  const { email, otp } = req.body;

  const user = await User.findOne({
    email,
    otp_expiry_time: { $gt: Date.now() },
  });

  if (!user) {
    res.status(400).json({
      status: "error",
      message: "Email is invalid or OTP expired",
    });
  }

  if(user.verified){
    return res.status(400).json({
      status: "error",
      message: "Email is already verified"
    });
  }

  if (!(await user.correctOTP(otp, user.otp))) {
    res.status(400).json({
      status: "error",
      message: "OTP is incorrect",
    });
    return;
  }

  // OTP is correct
  user.verified = true;
  user.otp = undefined;
  await user.save({ new: true, validateModifiedOnly: true });

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "OTP verified successfully!",
    token,
    user_id: user._id
  });
});

  // User Login
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({
      status: "error",
      message: "Both email and password are required",
    });
    return;
  }

  const user = await User.findOne({ email: email }).select("+password");

  if(!user || !user.password){
    res.status(400).json({
      status: "error",
      message: "Incorrect password"
    });
    return;
  }

  if (!user || !(await user.correctPassword(password, user.password))) {
    res.status(400).json({
      status: "error",
      message: "Email or password are incorrect",
    });
    return;
  }

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "Logged in successfully",
    token,
    user_id: user._id
  });
});

exports.protect = async (req, res, next) => {
  // 1) Getting token (JWT) and check if it's there

  let token;

  // 'Bearer iushruh364453kjbu345bjk34

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  } else {
    req.status(400).json({
      status: "error",
      message: "You are not logged in! Please log in to get access.",
    });
    return;
  }

  // 2) verification of token

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exists

  const this_user = await User.findById(decoded.userId);

  if (!this_user) {
    res.status(400).json({
      status: "error",
      message: "The user doesn't exist",
    });
  }

  // 4) Check if user changed their password after token was issued

  if (this_user.changedPasswordAfter(decoded.iat)) {
    res.status(400).json({
      status: "error",
      message: "User recently updated password! Please log in again.",
    });
  }

  //
  req.user = this_user;
  next();
};

exports.forgotPassword = async (req, res, next) => {
  // 1) Get users email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    res.status(400).json({
      status: "error",
      message: "There is no user with given email address",
    });
    return;
  }

  // 2) Generate the random reset token
  const resetToken = user.createPasswordResetToken();

  const resetURL = `https://tawk.com/auth/reset-password/?code=${resetToken}`;

  try {
    // TODO => Send Email With Reset URL

    res.status(200).json({
      status: "success",
      message: "Reset Password link sent to Email",
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save({ validateBeforeSave: false });

    res.status(500).json({
      status: "error",
      message: "There was an error sending the email. Please try again later",
    });
  }
};

exports.resetPassword = async (req, res, next) => {
  // 1) Get user based on token

  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // 2) If token has expired or submission is out of time window

  if (!user) {
    res.status(400).json({
      status: "error",
      message: "Token is invalid or expired",
    });
    return;
  }

  // 3) Update user password and set resetToken & expiry to undefined

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save();

  // 4) Log in the user and send new JWT

  // TODO => send an email to user informing about password reset

  const token = signTOken(userDoc._id);

  res.status(200).json({
    status: "success",
    message: "Password reseted successfully",
    token,
  });
};
