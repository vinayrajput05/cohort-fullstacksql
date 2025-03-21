import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import userRoutes from './routes/user.routes.js'

const port = process.env.PORT || 4000;

const app = express()

app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cors({
    origin: 'http://127.0.0.1:3000',
    credentials: true,
}));

app.use('/api/v1/users', userRoutes)

app.listen({ port: port, host: '0.0.0.0' }, (err) => {
    if (err) {
        console.log('Failed to start', err);
        return;
    }
    console.log(`Server running on http://127.0.0.1:${port}`);
})
