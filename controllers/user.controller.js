import { PrismaClient } from '@prisma/client'
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import smtp from '../utils/smtp.js';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient()

const register = async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        if (!name || !email || !phone || !password) {
            return res.status(400).json({ message: "All fields are required" })
        }
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: "User already exist" })
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const verificationToken = crypto.randomBytes(32).toString('hex')

        const data = {
            name,
            phone,
            email,
            password: hashedPassword,
            verificationToken,
        }

        const user = await prisma.user.create({ data });

        // Send Email
        smtp.sendVerification(user);

        res.json({
            message: "Account created successfully"
        })
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }
}

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "All fields are required" })
        }
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: "User not found" })
        }

        if (!user.isVerified) {
            return res.status(401).json({ message: "Account not verified" })
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials" })
        }

        const accessToken = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: '1 m' });
        const refreshToken = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_REFRESH_SECRET, { expiresIn: '1d' });

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            maxAge: 24 * 60 * 60 * 1000
        }

        res.cookie('accessToken', accessToken, cookieOptions)
        res.cookie('refreshToken', refreshToken, cookieOptions)

        res.json({
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role,
            },
        })
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }
}

const verify = async (req, res) => {
    try {
        const { token } = req.params;

        const user = await prisma.user.findFirst({ where: { verificationToken: token } });

        if (!user) {
            return res.status(404).json({ message: "User not found" })
        }

        const data = { isVerified: true, verificationToken: null }
        await prisma.user.update({ where: { id: user.id }, data });

        res.json({
            message: "Account verified successfully"
        })
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }
}

const resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password, confirmPassword } = req.body
        if (!token) {
            return res.status(401).json({ message: "Invalid token" })
        }

        if (password != confirmPassword) {
            return res.status(401).json({ message: "Confirm Password not match" })
        }

        const user = await prisma.user.findFirst({
            where: {
                passwordResetToken: token,
                passwordResetExpiry: { gt: new Date() } // ✅ Correct way
            }
        });

        if (!user) {
            return res.status(401).json({ message: "Token expire" })
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const data = { password: hashedPassword, passwordResetToken: null, passwordResetExpiry: null }
        await prisma.user.update({ where: { id: user.id }, data })

        res.json({ message: "Password reset successfully" })
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }
}

const resetPasswordForm = async (req, res) => {
    try {
        const { token } = req.params;
        if (!token) {
            return res.status(401).json({ message: "Invalid token" })
        }

        res.send(`<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset Password</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="flex items-center justify-center min-h-screen bg-gray-100">
                <div class="w-full max-w-md p-6 bg-white rounded-lg shadow-md">
                    <h2 class="text-2xl font-semibold text-center text-gray-700">Reset Password</h2>
                    <form id="resetForm" action="" method="POST" class="mt-4">
                        <div class="mb-4">
                            <label class="block text-sm font-medium text-gray-700">New Password</label>
                            <input type="password" id="password" name="password" class="w-full px-4 py-2 mt-1 border rounded-md focus:ring focus:ring-blue-300" required>
                        </div>
                        <div class="mb-4">
                            <label class="block text-sm font-medium text-gray-700">Confirm Password</label>
                            <input type="password" id="confirmPassword" name="confirmPassword" class="w-full px-4 py-2 mt-1 border rounded-md focus:ring focus:ring-blue-300" required>
                        </div>
                        <button type="submit" class="w-full px-4 py-2 text-white bg-blue-500 rounded-md hover:bg-blue-600">Reset Password</button>
                    </form>
                </div>
            </body>
            </html>
`)
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }
}

const passwordResetLink = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ message: "All fields are required" })
        }
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: "User not found" })
        }

        const passwordResetToken = crypto.randomBytes(32).toString('hex');
        const passwordResetExpiry = new Date(Date.now() + (10 * 60 * 1000));
        const data = { passwordResetToken, passwordResetExpiry }
        const updatedUser = await prisma.user.update({ where: { id: user.id }, data });

        smtp.sendPasswordResetLink(updatedUser);

        res.json({
            message: "Password reset email send successfully"
        })
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }
}

const refreshToken = async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(400).json({ message: "Invalid token" })
        }

        const decode = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
        if (!decode) {
            return res.status(401).json({ message: "Invalid token" })
        }

        const user = await prisma.user.findUnique({ where: { id: decode.userId } });
        if (!user) {
            return res.status(404).json({ message: "User not found" })
        }

        const accessToken = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: '1 m' });
        const refreshToken = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_REFRESH_SECRET, { expiresIn: '1d' });

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            maxAge: 24 * 60 * 60 * 1000
        }

        res.cookie('accessToken', accessToken, cookieOptions)
        res.cookie('refreshToken', refreshToken, cookieOptions)

        res.json({ accessToken, refreshToken })
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }
}

const me = async (req, res) => {
    try {
        const user =await prisma.user.findUnique({ where: { id: req.userId } })

        if (!user) {
            return res.status(404).json({ message: "User not found" })
        }

        res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
        });
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }

}

export {
    register,
    login,
    verify,
    resetPassword,
    resetPasswordForm,
    passwordResetLink,
    refreshToken,
    me
}