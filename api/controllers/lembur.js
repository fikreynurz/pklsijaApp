const Lembur = require('../models/lembur')
const User = require('../models/user')
const mongoose = require('mongoose')
const mailer = require('./nodemailer')

exports.lembur_get_all = async (req, res, next) => {
    const docs = await Lembur.find()
        // .select('-__v')
        // .exec()
        // .then(docs => {
            let docsi = await Promise.all( docs.map( async (doc)  => {
                const { _id, assigner, ...docum } = doc._doc;
                const monde = await User.findById(doc.assigner);
                docum.assigner = monde.username;
                docum.id = doc._id;
                // console.log(monde.username);
                return docum;
            }))
            // if(docs.length >= 0){
            res.status(200).json({total: docsi.length,data: docsi})
            // }else {
            //     res.status(404).json({
            //         message: 'No entries'
            //     })
            // }
        // })
        // .catch(err => {
        //     console.log(err)
        //     res.status(500).json({
        //         error: err
        //     })
        // })
}

exports.lembur_create = async (req, res, next) => {
    let count = ( "000" + (await Lembur.count() + 1 )).slice(-3)
    // const total = Lembur.countDocuments()
    let now = new Date()
    let y2d = now.getFullYear().toString().substr(-2)
    let m2d = ("0" + (now.getMonth() + 1)).slice(-2)
    let d2d = ("0" + (now.getDate())).slice(-2)
    let documentId = `${y2d}/${m2d}/${d2d}/${count}`
    let createdDate = `${d2d}/${m2d}/${y2d}`
    let assigner = await User.findById(req.body.assigner);

    const lembur = new Lembur({
        _id: new mongoose.Types.ObjectId(),
        documentId: documentId,
        createdDate: createdDate,
        fullName: req.userData.username, // ngambil dari req, check-auth
        assigner: req.body.assigner,
        reasons: req.body.reasons,
        time: req.body.time,
        startTime: req.body.startTime,
        endTime: req.body.endTime,
        // lemburImage: req.file.path
    })
    lembur.save()      
    .then(result => {
        console.log(result)
        mailer.send_email(lembur, assigner.email)
        res.status(201).json({
            message: "Created!"
        })
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({
            error: err
        })
    })
}

exports.lembur_get_one = (req, res, next) => {
    const id = req.params.lemburId
    Lembur.findById(id)
        .select('-__v')
        .exec()
        .then(doc => {
            console.log(doc)
            if (doc) {
                res.status(200).json(doc)
            } else {
                res.status(404).json({
                    message: 'No valid'
                })
            }
        })
        .catch(err => {
            console.log(err)
            res.status(500).json({ error: err })
        })
}

exports.lembur_patch = (req, res, next) => {
    const id = req.params.lemburId
    const updateOps = {}
    for (const ops of req.body) {
        updateOps[ops.propName] = ops.value
    }
    Lembur.updateOne({ _id: id }, { $set: updateOps })
        .exec()
        .then(result => {
            console.log(result)
            res.status(200).json({ result })
        })
        .catch(err => {
            console.log(err)
            res.status(500).json({
                error: err
            })
        })
}

exports.lembur_delete = (req, res, next) => {
    const id = req.params.lemburId
    Lembur.remove({ _id: id })
        .exec()
        .then(result => {
            console.log(result)
            res.status(200).json({
                message: 'Deleted'
            })
        })
        .catch(err => {
            console.log(err)
            res.status(500).json({
                error: err
            })
        })
}

exports.lembur_deleteAll = (req,res) => {
    Lembur.remove()
    .exec()
    .then(hapus => {
        console.log(hapus)
        res.status(200).json({
            message: "All data deleted!"
        })
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({
            error: err
        })
    })
}