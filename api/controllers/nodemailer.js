exports.send_email = (lembur, email) => {
    require('dotenv').config()
    
    const nodemailer = require('nodemailer')
    
    let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'pklsija2021@gmail.com',
            pass: process.env.PASSWORD
        }
    })
    
    let mailOptions = {
        from: '"PKL SIJA 2021"<pklsija2021@gmail.com>',
        to: email,
        subject: 'Izin Lembur Pegawai PT. GTI',
        text: `Nama\t\t : ${lembur.fullName}\nAlasan\t\t : ${lembur.reasons}\nJam\t\t : ${lembur.startTime.toLocaleTimeString()} - ${lembur.endTime.toLocaleTimeString()}`
    }
    
    transporter.sendMail(mailOptions, function(err, data) {
        if(err) {
            console.log(err)
        }else {
            console.log('Mail Sent!')
        }
    })
}

