const sgMail = require("@sendgrid/mail");

const dotenv = require("dotenv");

dotenv.config({ path: "../config.env" });

sgMail.setApiKey(process.env.SG_KEY);

const sendSGMail = async ({
  recipient,
  sender,
  subject,
  html,
  text,
  attachments,
}) => {
  try {
    //below block gpt
    if(!recipient){
      throw new Error("Recipient email address is required")
    }
    //
    const from = sender || "joeidelson@gmail.com"; //CHANGE THIS EMAIL ADDRESS LATER

    const msg = {
      to: recipient, // email of recipient
      from: from, // this will be our verified sender
      subject, //shorthand for key/value being the same
      html: html || text, //altered this line gpt added "html ||"
      text: text,
      attachments,
    };

    return await sgMail.send(msg); //added await
  } catch (error) {
    console.log(error);
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
