const jwt = require('jsonwebtoken');
const User = require('../models/user')


module.exports = (...roles) => {
    return async function (req, res, next) {
        try {
            const token = req.headers.authorization.split(" ")[1];
            const decoded = jwt.verify(token, process.env.JWT_KEY);
            req.userData = await User.findById(decoded.id);
            if (!roles.includes(req.userData.roles) && roles.length) { // aksen nanya
                console.log(roles, req.userData.roles)
                return res.status(401).json({
                    message: 'No Access'
                });
            }
            next();
        } catch (error) {
            return res.status(401).json({
                message: 'Authentication failed'
            });
        }
    }
};