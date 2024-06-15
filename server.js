import express from 'express';
import cors from 'cors';
import { User, db } from './firebase.js';
import validator from 'validator';
import nodemailer from 'nodemailer';
const require = createRequire(import.meta.url);
const dotenv = require('dotenv');
dotenv.config();
import { addDoc, collection, doc, getDoc, getDocs, query, updateDoc, where } from 'firebase/firestore';

import cookieParser from 'cookie-parser';


import EmailValidation from 'fakemail-guard';
import bcrypt from 'bcryptjs';
// dotenv.config({
//     path: "./env"
// });


const app = express();
app.use(express.json());
app.use(cors());
app.use(cookieParser());

const ev = new EmailValidation();



const isValidPassword = (password) => {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return regex.test(password);
};


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EmailPassword
    }
});

const sendConfirmationEmail = (email) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Confirmation Email',
        text: 'Thank you for signing up!'
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
};



app.post('/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;

        if (!validator.isEmail(email)) {
            return res.status(401).send({ error: 'Invalid email', success: false });
        }

        if (!ev.check(email)) {
            return res.status(401).send({ error: 'Invalid email', success: false });
        }

        const q = query(collection(db, 'users'), where("email", "==", email));
        const querySnapshot = await getDocs(q);

        if (!querySnapshot.empty) {
            return res.status(401).json({ success: false, error: "User already exists" });
        }

        if (!isValidPassword(password)) {
            return res.status(401).send({ error: 'Password strong password required', success: false });
        }

        const hashPassword = await bcrypt.hash(password, 10);
        const data = { firstName, lastName, email, password: hashPassword };
        const userRef = await addDoc(collection(db, "users"), data);

        sendConfirmationEmail(email);
        res.cookie("user", userRef.id, {
            httpOnly: true,
            secure: true
        })
        return res.status(201).json({ success: true, user: userRef.id });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal Server Error", success: false });
    }
});




app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!validator.isEmail(email)) {
        return res.status(401).send({ error: 'Invalid email', success: false });
    }

    try {
        const q = query(collection(db, 'users'), where("email", "==", email));
        const querySnapshot = await getDocs(q);

        if (querySnapshot.empty) {
            return res.status(404).json({ error: "No user found", success: false });
        }

        const docId = querySnapshot.docs[0].id;
        const resetLink = `${process.env.FRONT_END}/reset-password/${docId}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset',
            text: `Please click the following link to reset your password: ${resetLink}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).send({ error: 'Failed to send password reset email', success: false });
            } else {
                return res.status(200).send({ message: 'Password reset email sent successfully', success: true });
            }
        });
    } catch (error) {
        console.log(error);
        return res.status(500).send({ error: "Internal Server Error", success: false });
    }
});



app.post('/change-pass', async (req, res) => {
    try {
        const { userId, password } = req.body;

        if (!userId) {
            return res.status(400).send({ error: "User ID is required", success: false });
        }

        if (!password) {
            return res.status(400).send({ error: "Password is required", success: false });
        }

        const userDocRef = doc(db, 'users', userId);
        const userDoc = await getDoc(userDocRef);

        if (!userDoc.exists()) {
            return res.status(404).json({ error: "No user found", success: false });
        }

        const newPasswordHash = await bcrypt.hash(password, 10);

        await updateDoc(userDocRef, { password: newPasswordHash });

        return res.status(200).json({ success: true });
    } catch (error) {
        console.log(error);
        return res.status(500).send({ error: "Internal Server Error", success: false });
    }
});



app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required", success: false });
        }

        const q = query(collection(db, 'users'), where("email", "==", email));
        const querySnapshot = await getDocs(q);

        if (querySnapshot.empty) {
            return res.status(401).json({ error: "User not found", success: false });
        }

        const userDoc = querySnapshot.docs[0];
        const userData = userDoc.data();

        const isPasswordValid = await bcrypt.compare(password, userData.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid password", success: false });
        }

    
        res.cookie('user', userDoc.id, {
            httpOnly: true,
            secure: true
        });

        return res.status(200).json({ success: true, user: { id: userDoc.id, email: userData.email } });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "Internal Server Error", success: false });
    }
});




app.post("/operation", (req, res) => {
    try {
        const { num1, num2, operation } = req.body;
        let result = undefined;
        if (operation == "sum") {
            result = num1 + num2;
        } else if (operation == "substraction") {
            result = num1 - num2;
        } else if (operation == "multiplication") {
            result = num1 * num2;
        } else {
            return res.status(200).json({ success: false, error: "operation type not defined" });
        }
        res.status(200).json({ success: true, result })
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "Internal Server Error", success: false });
    }
})

app.listen(5000, () => {
    console.log('App is running on port 5000');
});


