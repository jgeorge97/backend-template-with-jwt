const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const User = require('../models/User');

class AuthController {
    register = async (req, res, next) => {
        console.log(req.body);
        const { name, email, password } = req.body;
        console.log(req.body);
        const user = new User(req.body);

        const salt = await bcrypt.genSalt(Number(process.env.SALT));
        user.password = await bcrypt.hash(user.password, salt);
        await user.save();

        res.send(user);
    }

    login = async (req, res, next) => {
        try {
            const user = await User.findOne({ email: req.body.email });
            if (!user) return res.status(400).send("Invalid email or password");

            const validPassword = await bcrypt.compare(
                req.body.password,
                user.password
            );
            if (!validPassword)
                return res.status(400).send("Invalid email or password");

            const token = user.generateAuthToken();
            res.send(token);
        } catch (error) {
            console.log(error);
            res.send("An error occured");
        }
    }

    profile = async (req, res, next) => {
        try {
            const user = await User.findById(req.user._id).select("-password -__v");
            res.send(user);
        } catch (error) {
            console.log(error);
            res.send("An error occured");
        }
    }
}

module.exports = AuthController;