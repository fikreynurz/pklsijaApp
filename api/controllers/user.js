const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../models/user')
const checkAuth = require('../middleware/check-auth')

exports.user_signup = (req,res,next) => {
    User.find({email: req.body.email})
    .exec()
    .then(user => {
        if(user.length >= 1){
            return res.status(409).json({
                message: 'Email already taken!'
            })
        }else {
            bcrypt.hash(req.body.password, 10, (err, hash) => {
                if(err){
                    return res.status(500).json({
                        error:err
                    })
                }else {
                    const user = new User({
                        _id: mongoose.Types.ObjectId(),
                        username: req.body.username,
                        email: req.body.email,
                        password: hash,
                        roles: req.body.roles
                    })
                    user.save()
                    .then(result => {
                        console.log(result)
                        res.status(200).json({
                            message: "User Created!"
                        })
                    })
                    .catch(err => {
                        console.log(err)
                        res.status(500).json({
                            error:err
                        })
                    })
                }
            })
        }
    })
}

exports.user_signin = async (req,res,next) =>{
    User.find({email: req.body.email})
    .exec()
    .then(user => {
        if(user.length <1 ) {
            return res.status(401).json({
                message: 'No user'
            })
        }
        bcrypt.compare(req.body.password, user[0].password, (err, hasil) => {
            if (err){
                return res.status(401).json({
                    message: 'email or password salah'
                }) 
            }
            if (hasil) {
                const token = jwt.sign({
                    email: user[0].email,
                    id: user[0]._id
                }, process.env.JWT_KEY, 
                {
                    // expiresIn: "1h"
                }
                );
                return res.status(200).send({
                    id: user[0]._id,
                    username: user[0].username,
                    email: user[0].email,
                    roles: user[0].roles,
                    token: token
                })
            }
            res.status(401).json({
                message: 'Auth failed (pw compare)'
            })
        })
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({
            error:err
        })
    })
}

exports.user_getAll = async (req,res) => {
    let users = await User.find();
    users = users.map(user => {
        const {_id, ...monde } = user._doc
        monde.id = user._id;
        return monde;
    })
    res.send(users)
}

exports.user_getManager = async (req,res) => {
    let users = await User.find({
        roles: 'management'
    })
    users = users.map(user => {
        const {_id, ...monde } = user._doc
        monde.id = user._id;
        return monde;
    })
    res.send(users)
}


exports.user_delete = (req,res,next) => {
    User.remove({id:req.params.userId})
    .exec()
    .then(hasil => {
        res.status(200).json({message:'User deleted'})
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({
            error:err
        })
    })
}
