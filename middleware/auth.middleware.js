import jwt from "jsonwebtoken";

const auth = async (req, res, next) => {
    try {
        const { accessToken } = req.cookies;

        const decode = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);
        if (!decode) {
            return res.status(401).json({ message: "Invalid token" })
        }
        req.userId = decode.userId;

        next();
    } catch (error) {
        res.status(500).json({ message: "Server error", error })
    }
}

export default auth