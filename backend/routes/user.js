const express = require('express');
const connection = require('../connection');
const router = express.Router()
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer')
require('dotenv').config();
var auth = require('../services/authentication')
var checkRole = require('../services/checkRole')

router.post('/signup',(req,res)=>{
   let user = req.body;
   query = "select email,password,role,status from user where email=?";
   connection.query(query,[user.email],(err,results)=>{
    if(!err){
      if(results.length <= 0){
        query = "insert into user(name,contactNumber,email,password,status,role) values(?,?,?,?,'false','user')";
        connection.query(query,[user.name,user.contactNumber,user.email,user.password],(err,results)=>{
          if(!err){
               return res.status(200).json({message:"succesfulle Registered"})
          }else{
            return res.status(500).json(err)
          }
        })
      }
      else{
        return res.status(400).json({message:"Email already exist"})
      }
    }else{
        return res.status(500).json(err)
    }
   })
})


router.post('/login',(req,res)=>{
  const user = req.body;
  query = "select email,password,role,status from user where email=?"
  connection.query(query,[user.email],(err,result)=>{
   if(!err){
    if(result.length <=0 || result[0].password !=user.password){
      return res.status(401).json({message:"Incorrect Email or password"})
    }else if(result[0].status === 'false'){
       return res.status(401).json({message:"wait for admin approval"})
    }else if(result[0].password == user.password){
         const response = {email:result[0].email, role:result[0].role};
         const accessToken = jwt.sign(response,process.env.ACCESS_TOKEN,{expiresIn:30*60})
         res.status(200).json({token:accessToken})
    }
   }else{
    return res.status(500).json(err)
   }
  })
})

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth:{
    user: process.env.EMAIL,
    pass: process.env.PASSWORD
  }
})
router.post('/forgotPassword',(req,res)=>{
  const user = req.body;
  query ="select email,password,role,status from user where email=?"
  connection.query(query,[user.email],(err,result)=>{
    if(!err){
      if(result.length <=0){
        return res.status(401).json({message:"email does not exist "})
      }else{
        var mailOptions ={
          from: process.env.EMAIL,
          to: result[0].email,
          subject: 'Password by Pro compu Manager',
          html:'<p><b>Your login details for PRO COMPU Management System</b><br><b>Email: </b>'+result[0].email+'<br><b>Password: </b>'+result[0].password+'<br><a href="http://localhost:4200/login">Click here to login</a></p>'
        };

        transporter.sendMail(mailOptions, (err, info) => {
          if (err) {
              console.error('Error sending email:', err);
              return res.status(500).send(err);
          } else {
              console.log('Email sent:', info.response);
              return res.status(200).json({ message: "Password sent successfully to your email." });
          }
      });
      
        return res.status(200).json({message:"Password sent successfully to your email."});
      }
    }else{
      return res.status(500).json(err)
    }
  })
})

router.get('/getUser',auth.authenticateToken,checkRole.checkRole,(req,res)=>{
  var query = "select id,name,email,contactNumber,status from user where role='user'"
  connection.query(query,(err,result)=>{
    if(!err){
        return res.status(200).json(result)
    }else{
      return res.status(500).send(err)
    }
  })
})

router.patch('/update',auth.authenticateToken,(req,res)=>{
  let user = req.body
  var query = "update user set status=? where id=?"
  connection.query(query,[user.status,user.id],(err,result)=>{
    if(!err){
       if(result.affectedRows ==0){
        return res.status(404).json({message:"User does not exist"})
       }
       return res.status(200).json({message:"User Updated Successfully"})
    }else{
      return res.status(500).json(err)
    }
  })
})

router.post('/changePassword',auth.authenticateToken,(req,res)=>{
  const user = req.body;
  const email= res.locals.email;
  var query= "select *from user where email=? and password=?";
  connection.query(query,[email,user.oldPassword],(err,result)=>{
    if(!err){
        if(result.length <=0){
          return res.status(400).json({message:"incorrect Old Password"});
        }
        else if (result[0].password == user.oldPassword){
             query="update user set password=? where email=?";
             connection.query(query,[user.newPassword,email],(err,result)=>{
               if(!err){
                return res.status(200).json({message:"Password Updated Successfully"})

               }else{
                return res.status(500).send(err);
               }
             })
        }else{
          return res.status(400).json({message:"Something went wrong. Please try again later"})
        }
    }else{
      return res.status(500).send(err)
    }
  })
   
})
module.exports = router