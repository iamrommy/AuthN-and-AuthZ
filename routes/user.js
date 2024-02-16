const express = require('express');
const router = express.Router();
const User = require('../models/userModel');

const {login, signUp} = require('../controllers/Auth');
const {auth, isStudent, isAdmin} = require('../middlewares/auth');

router.post('/login', login);
router.post('/signup', signUp);

//Protected Routes
router.get('/test', auth, (req,res)=>{
    res.json({
        success:true,
        message:'Welcome to the Protected route for TESTS'
    })
})

router.get('/student', auth, isStudent, (req,res)=>{
    res.json({
        success:true,
        message:'Welcome to the Protected Route for Students'
    })
})

router.get('/admin', auth, isAdmin, (req,res)=>{
    res.json({
        success:true,
        message:'Welcome to the Protected Route for Admin'
    })
})

router.get('/getinfo', auth, async (req, res)=>{

    try{
        const id = req.user.id; //user will be added in req by auth middleware. also user or payload had the user id when jwt was created
        console.log("ID: ", id);
        
        const user = await User.findById(id); //So that id can be used to find the whole info of user from database

        res.status(200).json({
            success:true,
            user:user,
            message: 'Welcome to the email route'
        })

    } catch(error){
        res.status(500).json({
            success:false,
            error:error,
            message: 'Error in get Info route'
        })        
    }
})

module.exports = router;
