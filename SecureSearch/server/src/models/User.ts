import mongoose, { Schema } from "mongoose";
export interface IUser {
  name: string; email: string; passwordHash: string;
}
const userSchema = new Schema<IUser>({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true });
export const User = mongoose.model<IUser>("User", userSchema);
