const bcrypt = require('bcryptjs');

const User = require('../models/User');

class AuthController {
    register = async (req, res, next) => {
        const user = new User(req.body);

        const salt = await bcrypt.genSalt(Number(process.env.SALT));
        user.password = await bcrypt.hash(user.password, salt);
        await user.save();

        res.send({ error: false, msg: "User Created!!"});
    }

    login = async (req, res, next) => {
        try {
            const user = await User.findOne({ email: req.body.email });
            if (!user) return res.status(400).send({ error: true, msg: "Invalid email or password"});

            const validPassword = await bcrypt.compare(
                req.body.password,
                user.password
            );
            if (!validPassword)
                return res.status(400).send({ error: true, msg: "Invalid email or password"});

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