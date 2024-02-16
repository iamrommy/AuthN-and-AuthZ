const jwt = require('jsonwebtoken');
require('dotenv').config();

exports.auth = (req, res, next) =>{ 
    try{
      
        const token = req.cookies.token || req.body.token || req.header("Authorization").replace("Bearer ", ""); 
        console.log(token);
        if(!token || token === undefined){ //if token not available
            return res.status(401).json({
                success:false,
                message:'Token is Missing'
            })
        }

        //verify the token
        try{
            const decode = jwt.verify(token, process.env.JWT_SECRET); //check if jwt token is valid by verify method by passing Jwt secret
            console.log(decode); 

            req.user = decode; //now we will store that object as user in req to process the role of user in further middlewares
        }
        catch(error){
            return res.status(401).json({
                success: false,
                message: 'token is invalid'
            })
        }
        
        next(); //calling next middlewares

    }
    catch(error){
        return res.status(401).json({
            success: false,
            message: 'Something went wrong while verifying the token'
        })
    }
}

exports.isStudent = (req, res, next)=>{ //Middleware for student authorization
    try{
        if(req.user.role !== 'Student'){ //now using the user object which was stored erlier to verify role of user
            return res.status(401).json({
                success:false,
                message:"Protected for students"
            })
        }

        next();
    }
    catch(error){
        return res.status(500).json({
            success: false,
            message: 'User Role is not matching'
        })
    }
}

exports.isAdmin = (req, res, next)=>{ //middleware for admin authorization
    try{
        if(req.user.role !== 'Admin'){
            return res.status(401).json({
                success:false,
                message:"Protected for admin"
            })
        }

        next();
    }
    catch(error){
        return res.status(500).json({
            success: false,
            message: 'User Role is not matching'
        })
    }
}