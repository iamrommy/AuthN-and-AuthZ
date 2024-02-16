const bcrypt = require('bcrypt');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken'); 
require('dotenv').config();

//signup route handler
exports.signUp = async (req,res)=>{
    try{
        // get data
        const {name,email,password,role} = req.body;

        //Check if user already exists
        const existingUser = await User.findOne({email});

        if(existingUser){
            return res.status(400).json({
                success:false,
                message:"User already exists"
            })
        }

        //secure password
        let hashedPassword;
        try{
            hashedPassword = await bcrypt.hash(password, 10);
        }
        catch(err){
            return res.status(500).json({
                success:false,
                message: 'Error in Hashing Password',
            })
        }

        const user = await User.create({
            name, email, password:hashedPassword, role
        })

        return res.status(200).json({
            success:true,
            message:"User Created Successfully"
        })

    }
    catch(err){
        console.error(err);
        return res.status(500).json({
            success: false,
            message: 'User cannot be registered, please try again later'
        })
    }
}

//login
exports.login = async (req, res)=>{
    try{
        //data fetch
        const {email, password} = req.body;

        //validation on email and password
        if(!email || !password){
            return res.status(400).json({
                success:false,
                message: "please fill all the details carefully"
            })
        }

        //check for registered user
        let user = await User.findOne({email}); //We have made the user variable from let and not const as it will be updated later
        //if not a registered user
        if(!user){
            return res.status(401).json({
                success:false,
                message:"User is not registered"
            })
        }

        const payload = { //object which contains info about user which can be used to generate jwt tokens
            email: user.email,
            id:user._id,
            role: user.role
        }

        //verify password
        //Now we want to compare the entered password with hashed password. For this we have a bcrypt.compare() method
        if(await bcrypt.compare(password, user.password)){ 
            //password match
            //To create jwt token jwt.sign() method is used which takes 3 args 1) payload, 2) secret key and 3) options 
            let token = jwt.sign(payload, process.env.JWT_SECRET, {
                expiresIn: "2h" //jwt token will expire in 2 hours
            });

            user = user.toObject(); 
            user.token = token; //added token to user object
            user.password = undefined; //also make sure to remove password from user object to protect it from being hacked

            const options = { //options object passed in to cookie to tell the cookie's validity
                expires: new Date( Date.now() + 3*24*60*60*1000)
            }

            //create a cookie for storing info in local storage. 3 args are 1) Cookie name, 2) JWT token and 3) options
            res.cookie('token', token, options).status(200).json({ 
                success:true,
                token,
                user,
                message: 'User Logged in successfully'
            })

        }
        else{
            //passwords do not match
            return res.status(403).json({
                success: false,
                message: "Wrong Password"
            })
        }
    }
    catch(err){
        console.log(err);
        return res.status(500).json({
            success: false,
            message: "Login Failure"
        })
    }
}