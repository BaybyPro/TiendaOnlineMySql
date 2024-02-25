const express = require('express');
var cors = require('cors');
const connection = require('./connection')
const userRoute = require('./routes/user')
const categoryRouter = require('./routes/category')
const productRouter = require('./routes/product')
const billRouter = require('./routes/bill')
const dashboardRouter = require('./routes/dashboard')
const app = express();

app.use(cors());
app.use(express.urlencoded({extended:true}))
app.use(express.json());
app.use('/user',userRoute);
app.use('/category',categoryRouter);
app.use('/product',productRouter);
app.use('/bill',billRouter);
app.use('/dashboard',dashboardRouter)

module.exports = app;