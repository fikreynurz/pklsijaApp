const express = require('express')
const router = express.Router()
const mongoose = require('mongoose')
const checkAuth = require('../middleware/check-auth')
const LemburController = require('../controllers/lembur')

// modules for uploading file
// const multer = require('multer')
// const storage = multer.diskStorage({
//     destination: function(req,file,cb){
//         cb(null, './uploads')
//     },
//     filename:function(req,file,cb){
//         cb(null,Date.now() + file.originalname)
//     }
// })

// const fileFilter = (req, file, cb) => {
//     //reject file
//     if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png'){
//         cb(null, true)
//     }else {
//         cb(null, false)
//     }
// }

// const upload = multer({
//     storage:storage, 
//     limits: {
//         fileSize: 1024 * 1024 * 5
//     },
//     fileFilter:fileFilter
// })

const Lembur = require('../models/lembur')

router.get('/', checkAuth('management'), LemburController.lembur_get_all)

// upload.single('lemburImage'),

router.post('/', checkAuth(),LemburController.lembur_create)

router.get('/:lemburId', checkAuth('management'), LemburController.lembur_get_one)

router.patch('/:lemburId', checkAuth('management'), LemburController.lembur_patch)

router.delete('/:lemburId', checkAuth('management'), LemburController.lembur_delete)

router.delete('/', checkAuth('management'), LemburController.lembur_deleteAll)

module.exports = router