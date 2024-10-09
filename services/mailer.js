const sgMail = require("@sendgrid/mail");

sgMail.sendApiKey(process.env.SG_KEY);

const sendSGMail = async ({
  recipient,
  sender,
  subject,
  content,
  attachments,
}) => {
  try {
    const from = sender || "contact@example.in";

    const msg = {
      to: recipient, // email of recipient
      from: from, // this will be our verified sender
      subject, //shorthand for key/value being the same
      html: content,
      //text: ""
      attachments,
    };

    return sgMail.send(msg);
  } catch (error) {
    console.log(error);
  }
};


exports.sendEmail = async (args) => {
    if(process.env.NODE_ENV === "development"){
        return new Promise.resolve();
    }
    else {
        
    }
}

