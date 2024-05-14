import mongoose, { Schema } from "mongoose"
import jwt from 'jsonwebtoken'
import bcrpt from 'bcrypt'

const UserSchema = new Schema({
    name: {
        type: String
    },
    email: {
        type: String,
        unique: true
    },
    password: {
        type: String
    },
    avatar: {
        type: String,
        required: true,
    },
    refreshToken: {
        type: String,
    }
}, { timestamps: true })

UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();

    this.password = await bcrpt.hash(this.password, 10)
    next()
})


UserSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrpt.compare(password, this.password)
}

UserSchema.methods.generateAccessToken = function () {
    return jwt.sign(
        {
            _id: this._id,
            name: this.name,
            email: this.email,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

UserSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", UserSchema)