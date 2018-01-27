'use strict';
const nodemailer = require('nodemailer');
const fs = require('fs')


let applyParms = (content, parms) => {
    console.log("applyParms", parms)
    for(const key in parms){
        console.log(key)
        content = content.replace("{" + key + "}", parms[key])
    }
    return content
}

exports.sendEmailFromTemplate = (template, parms) => {
    //read file
    let htmlTemplate = './business/email_template/' + template + '.tpl'
    let textTemplate = './business/email_template/' + template + '.txt'
    fs.readFile(htmlTemplate, "utf8", function(errHtml, htmlData){
        fs.readFile(textTemplate, "utf8", function(errText, textData){
            sendTestEmail(applyParms(htmlData, parms), applyParms(textData, parms), parms);            
        })
    })
}

let sendTestEmail = (htmlBody, textBody, parms) => {
    // Generate test SMTP service account from ethereal.email
    // Only needed if you don't have a real mail account for testing
    nodemailer.createTestAccount((err, account) => {

        // create reusable transporter object using the default SMTP transport
        let transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            secure: false, // true for 465, false for other ports
            auth: {
                user: account.user, // generated ethereal user
                pass: account.pass  // generated ethereal password
            }
        });

        // setup email data with unicode symbols
        let mailOptions = {
            from: '"Do Not Reply" <donotreply@curator.biaschecker.org>', // sender address
            to: parms.toEmail, // list of receivers
            subject: 'Hello ✔', // Subject line
            text: textBody, // plain text body
            html: htmlBody // html body
        };

        // send mail with defined transport object
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return console.log(error);
            }
            console.log('Message sent: %s', info.messageId);
            // Preview only available when sending through an Ethereal account
            console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

            // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@blurdybloop.com>
            // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
        });
    });
}
