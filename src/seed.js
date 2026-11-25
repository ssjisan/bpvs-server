import "dotenv/config";
import { connect, Role, User } from "./db.js";
import { defaults } from "./permissions.js";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";
await connect();
for (const [name, permissions] of Object.entries(defaults))
  await Role.updateOne(
    { name },
    { $setOnInsert: { name, permissions, protected: true } },
    { upsert: true },
  );
const email = process.env.ADMIN_EMAIL?.toLowerCase(),
  password = process.env.ADMIN_PASSWORD;
if (
  !email ||
  !password ||
  password.length < 12 ||
  password.startsWith("replace-")
)
  throw Error("Set strong admin credentials");
const role = await Role.findOne({ name: "SUPER_ADMIN" });
await User.updateOne(
  { email },
  {
    $setOnInsert: {
      email,
      name: "System Administrator",
      role: role._id,
      passwordHash: await bcrypt.hash(password, 12),
    },
  },
  { upsert: true },
);
await mongoose.disconnect();
