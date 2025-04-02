import dotenv from "dotenv"
import connectDB from "./db/index.js"
import express from "express"
import { app } from "./app.js";

dotenv.config({
    path:'./.env'
});

// const app=express();

connectDB()
.then(()=>{
    app.listen(process.env.PORT || 3000, ()=>{
        console.log(`Server is running at:${process.env.PORT}`);
    });
})
.catch((err)=>{
    console.log("MONGO db connection failed !!!",err)
})
//require('mongoose').config({path:'./env'})






/*
import mongoose from "mongoose"
import { DB_NAME } from "./constants"
import express from "express"
const app =express()
(async()=>{
    try {
        await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
        app.on("error",(error)=>{
            console.log("ERROR:",error);
            throw error
        })
        app.listen(process.env.PORT,()=>{
            console.log(`App is listening on port ${process.env.PORT}`);
        })
    } catch (error) {
        console.error("ERROR:",error)
        throw err
    }
})()
*/