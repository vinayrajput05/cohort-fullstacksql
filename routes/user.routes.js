import express from 'express'
import { login, register, passwordResetLink, refreshToken, resetPassword, resetPasswordForm, verify, me } from '../controllers/user.controller.js';
import auth from '../middleware/auth.middleware.js';

const router = express.Router();

router.post('/register', register)
router.post('/login', login)
router.get('/verify/:token', verify)
router.post('/password-forgot', passwordResetLink)
router.get('/password-reset/:token', resetPasswordForm)
router.post('/password-reset/:token', resetPassword)
router.post('/refresh-token', refreshToken)
router.get('/me', auth, me)


export default router