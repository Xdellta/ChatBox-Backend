const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware')

router.post('/login', authController.login);
router.post('/logout', authMiddleware.verifyAccess, authController.logout);
router.post('/register', authController.register);
router.post('/refresh-token', authController.refreshToken);

module.exports = router;