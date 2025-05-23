import mongoose, {Schema} from "mongoose";
// import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";

const likeSchema= new Schema(
    {
        video:{
            type:Schema.Types.ObjectId,
            ref:"Video"
        },
        comment:{
            type:Schema.Types.ObjectId,
            ref:"Comment"
        },
        tweet:{
            type:Schema.Types.ObjectId,
            ref:"Tweet"
        },
        likedBy:{
            type:Schema.Types.ObjectId,
            ref:"User"
        }
    },
    {timestramps:true}
)

// commentSchema.plugin(mongooseAggregatePaginate)
export const Like=mongoose.model("Like",likeSchema)