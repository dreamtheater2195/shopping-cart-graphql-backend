const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomBytes } = require("crypto");
const { promisify } = require("util");
const { transport, emailTemplate } = require("../mail");
const { hasPermission } = require("../utils");
const Mutations = {
  async createItem(parent, args, ctx, info) {
    // TODO: Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error("You must be logged in to do that");
    }
    //ctx.db contains all mutations and query methods in generated prisma.graphql
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          user: {
            connect: {
              id: ctx.request.userId
            }
          },
          ...args
        }
      },
      info
    );

    return item;
  },
  async updateItem(parent, args, ctx, info) {
    // first take a copy of the updates
    const updates = { ...args };
    //remove the ID from the updates
    delete updates.id;
    //run the update method
    const item = await ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id
        }
      },
      info
    );
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    // find the item
    const item = await ctx.db.query.item({ where }, `{ id title }`);
    //Check if they own that item, or have the permissions

    //Delete it
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signup(parent, args, ctx, info) {
    //lowercase their email
    args.email = args.email.toLowerCase();
    //hash their password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permission: { set: ["USER"] }
        }
      },
      info
    );
    // create the JWT token for them
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    //set the jwt as a cookie on the res
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    return user;
  },
  async signin(parent, { email, password }, ctx, info) {
    // check if there is a user with the email
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }
    //check if there password is correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error("Invalid Password!");
    }
    //generate new token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    //set the cookie with the new token
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    //return the user
    return user;
  },
  signout(parent, args, ctx, info) {
    ctx.response.clearCookie("token");
    return { message: "Signed out." };
  },

  async requestReset(parent, { email }, ctx, info) {
    //Check if there is a real user
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }
    // set a reset token and expiry on that user
    const promiseRandomBytes = promisify(randomBytes);
    const resetToken = (await promiseRandomBytes(20)).toString("hex");
    const resetTokenExpiry = Date.now() + 60 * 60 * 1000; //1 hour from now;
    await ctx.db.mutation.updateUser({
      where: { email },
      data: { resetToken, resetTokenExpiry }
    });
    //email them the reset token
    const mailRes = await transport.sendMail({
      from: "dreamtheater2195@gmail.com",
      to: user.email,
      subject: "Your password reset token",
      html: emailTemplate(`<a href="${
        process.env.FRONTEND_URL
      }/reset?resetToken=${resetToken}">
      Click here to reset your password</a>`)
    });
    return { message: "Done generating reset token." };
  },
  async resetPassword(
    parent,
    { resetToken, password, confirmPassword },
    ctx,
    info
  ) {
    //check if password match
    if (password !== confirmPassword) {
      throw new Error("Confirm password not match");
    }
    //check if its a legit reset token
    //check if its expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken,
        resetTokenExpiry_gte: Date.now()
      }
    }); //resettoken: Date.now() + 1h > Date.now()
    if (!user) {
      throw new Error("The reset token is either invalid or expired");
    }
    //hash new password
    const newPassword = await bcrypt.hash(password, 10);
    //save the new password and remove reset token
    const updatedUser = await ctx.db.mutation.updateUser({
      where: {
        email: user.email
      },
      data: {
        password: newPassword,
        resetToken: null,
        resetTokenExpiry: null
      }
    });
    //generate jwt
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
    //set jwt cookie
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    //return user
    return updatedUser;
  },
  async updatePermissions(parent, { userId, permissions }, ctx, info) {
    //Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error("You must be logged in to do that");
    }
    const currentUser = await ctx.db.query.user(
      { where: { id: ctx.request.userId } },
      info
    );
    hasPermission(currentUser, ["ADMIN", "PERMISSIONUPDATE"]);

    //update permissions
    const updatedUser = await ctx.db.mutation.updateUser(
      {
        where: { id: userId },
        data: {
          permission: {
            set: permissions
          }
        }
      },
      info
    );
    return updatedUser;
  }
};

module.exports = Mutations;
