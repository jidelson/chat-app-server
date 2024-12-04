const sgMail = require("@sendgrid/mail");

const dotenv = require("dotenv");

dotenv.config({ path: "../config.env" });

sgMail.setApiKey(process.env.SG_KEY);


const sendSGMail = async ({ to, from, subject, text, html, attachments }) => {
  try {
    // for debugging register functionality, uncomment below
    // console.log("SendGrid Payload:", { to, from, subject, text, html, attachments }); // Log payload

    if (!to) {
      throw new Error("Recipient email address is required");
    }

    const msg = {
      to, // Recipient email
      from, // Verified sender email
      subject,
      text,
      html,
      attachments,
    };

    return await sgMail.send(msg);
  } catch (error) {
    console.error("Error sending email:", error.response?.body || error.message);
    throw error;
  }
};

exports.sendEmail = async (args) => {
  if (process.env.NODE_ENV === "development") {
    console.log("Email not sent in development mode. Args:", args);
    return Promise.resolve(); //removed "new" after return
  } else {
    return sendSGMail(args);
  }
};