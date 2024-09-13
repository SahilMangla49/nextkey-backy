const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const User = require('../models/User');
const authGuard = require('../middleware/authMiddleware');


router.post('/register', async (req, res) => {
    try {
        let user = await User.findOne({ email: req.body.email });

        if(user){
            return res.status(400).json({ message: 'User already exists' });
        }
        
        user = new User(req.body);

        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


router.post('/login', async (req, res) => {
    try{
        let user = await User.findOne({ email: req.body.email });

        if(!user){
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(req.body.password, user.password);

        if(!isMatch){
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        res.json({ token });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: error.message });
    }
});


router.get('/profile', authGuard, async (req, res) => {
    try {
        const user = req.user;

        res.json({
            id: user._id,
            name: user.name,
            email: user.email
        })
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

module.exports = router;