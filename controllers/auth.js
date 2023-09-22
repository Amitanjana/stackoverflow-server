import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import users from "../models/auth.js";

import { getAuth } from 'firebase-admin/auth'
import { initializeApp } from 'firebase-admin/app';
import admin from 'firebase-admin'
dotenv.config()

const credential=admin.credential
const firebaseApp = initializeApp({
  credential: credential.cert({
    "type": "service-account",
    "project_id": process.env.project_id,
    "private_key_id": process.env.private_key_id,
    "private_key": process.env.private_key,
    "client_email": process.env.client_email,
    "client_id": process.env.client_id,
  })
});


export const signup = async (req, res) => {
  dotenv.config();
  const { name, email, password } = req.body;
  try {
    const existinguser = await users.findOne({ email });
    if (existinguser) {
      return res.status(404).json({message: 'User already exists'});
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await users.create({
      name,
      email,
      password: hashedPassword,
    });
    const token = jwt.sign(
      { email: newUser.email, id: newUser._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(200).json({ result: newUser, token });
  } catch (error) {
    res.status(500).json({message:error.message});
    console.log(error);
  }
};


export const login = async (req, res) => {
  dotenv.config();
  const { email, password } = req.body;
  try {
    const existinguser = await users.findOne({ email });
    if (!existinguser) {
      return res.status(404).json({ message: "User don't exist." });
    }
    if (existinguser.isGoogle) {
      return res.status(401).json("sign in with Google");
    }
    const isPasswordCrt = await bcrypt.compare(password, existinguser.password);
    if (!isPasswordCrt) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign(
      { email: existinguser.email, id: existinguser._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(200).json({ result: existinguser, token });
  } catch (error) {
    console.log(error);
    res.status(500).json({message:error.message});
  }
};


export const loginWithGoogle = (req, res) => {

  const { userToken, name, email } = req.body;

  try {
    if (userToken) {
      getAuth(firebaseApp).verifyIdToken(userToken)
      .then(async (decodeUser) => {
        const existinguser = await users.findOne({ email: decodeUser.email })
        if (!existinguser) {
          const hashedPassword = await bcrypt.hash(decodeUser.uid, 12);
          const newUser = await users.create({
            name,
            email,
            password: hashedPassword,
            isGoogle:true
          });

          const token = jwt.sign(
            { email: newUser.email, id: newUser._id },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
          );
          return res.status(200).json({ result: newUser, token });
        }
        const token = jwt.sign(
          { email: existinguser.email, id: existinguser._id },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );
        res.status(200).json({ result: existinguser, token });
      })
      .catch(err=>{
        console.log(err)
        res.status(500).json({message:err.message})
      })
    }
  } catch (error) {
    console.log(error);
    res.status(500).json("somthing went wrong.");
  }
}
