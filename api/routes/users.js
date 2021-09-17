const express = require('express')
const router = express.Router()
const mongoose = require('mongoose')
const checkAuth = require('../middleware/check-auth')

const User = require('../models/user')
const UserController = require('../controllers/user')

router.get('/', checkAuth('management'),UserController.user_getAll)

router.get('/manager', checkAuth(), UserController.user_getManager)

router.post('/signup', UserController.user_signup)

router.post('/signin' , UserController.user_signin )

router.delete('/:userId', checkAuth('management'), UserController.user_delete)

module.exports = router

// kalo checkAuthnyah kosong, berti semua role