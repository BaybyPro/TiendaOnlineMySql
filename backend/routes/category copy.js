const express = require('express');
const connection = require('../connection');
const router = express.Router()
var auth = require('../services/authentication');
var checkRole = require('../services/checkRole');


router.post('/add',auth.authenticateToken,checkRole.checkRole,(req,res,next)=>{
    let category = req.body;
    query = "insert into category (name) values(?)";
    connection.query(query,[category.name],(err,result)=>{
        if(!err){
            return res.status(200).json({message:"Category added Successfully"});
        }else{
            return res.status(500).send(err);
        }
    })
})

router.get('/get',auth.authenticateToken,(req,res)=>{
    var query = "select *from category order by name";
    connection.query(query,(err,result)=>{
        if(!err){
            return res.status(200).json(result);
        }else{
            return res.status(500).send(err)
        }
    })
})

router.patch('/update',auth.authenticateToken,checkRole.checkRole,(req,res)=>{
    let product = req.body;
    var query = "update category set name=? where id=?"
    connection.query(query,[product.name,product.id],(err,result)=>{
        if(!err){
            if(result.affectedRows ==0){
               return res.status(404).json({message:"Category id does not found"})
            }
            return res.status(200).json({message:"Category Updated Successfully"})
        }else{
            return res.status(500).send(err);
        }
    })
})


router.delete('/delete',auth.authenticateToken,checkRole.checkRole,(req,res)=>{
    let  product = req.body;
    var query = "delete from category where id=?";
    connection.query(query,[product.id],(err,result)=>{
        if(!err){
            if(result.affectedRows ==0){
                return res.status(404).json({message:"Category id does not found"})
            }
            return res.status(200).json({message:"Category Delete Successfully"})
        }else{
            res.status(500).send(err)
        }
    })
})

module.exports = router;