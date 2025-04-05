import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";

// export const verifyJWT = asyncHandler(async(req,res,next)=>{
export const verifyJWT = asyncHandler(async(req,_,next)=>{
    try {
        const token=req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","")
        if (!token) {
            throw new ApiError(401,"Unauthorised request")
        }
        // console.log("Loaded ACCESS_TOKEN_SECRET:", process.env.ACCESS_TOKEN_SECRET);
        // console.log("Extracted Token:", token);
        // console.log("Decoded Token (before verification):", jwt.decode(token));

        const decodedToken = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
        const user = await User.findById(decodedToken?._id).select("-password -refreshtoken")
    
        if (!user) {
            throw new ApiError(401,"Invalid access token")
        }    
    
        req.user=user;
        next()
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid access token")
    }

})