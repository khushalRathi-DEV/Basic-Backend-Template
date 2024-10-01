const express = require("express");
const { UserModel, TodoModel } = require("./db");
const { auth, JWT_SECRET } = require("./auth");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const { z } = require("zod");


mongoose.connect("YOUR MONGO URL")

const app = express();
app.use(express.json());

app.post("/signup", async function(req, res) {
    const requiredBody = z.object({ //whatever is our desired format/ whatever we want to validate we should make a zod object and put it in
        email: z.string().min(3).max(19).email(),
        name : z.string().min(3).max(25),
        password: z.string().min(8).max(40)
    });
    
    const parsedDataWithSuccess = requiredBody.safeParse(req.body);
    if(!parsedDataWithSuccess.success){
        res.json({
            message : "Incorrect format",
            error : parsedDataWithSuccess.error
        })
        return
    }

    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;
    try {                          //added try catch blocks to prevent the backend from crashing,incase a user signups from a same email twice
        const hashedPassword = await bcrypt.hash(password, 5);
    
        await UserModel.create({
            email: email,
            password: hashedPassword, // we are pushing the hashed password in the db instead of original password
            name: name
        });  
        res.json({
            message: "You are signed up"
        })
    } catch (error) {
        res.json({
            message : "User already exists"
        })
    }
    
});


app.post("/signin", async function(req, res) {
    const email = req.body.email;
    const password = req.body.password;

    const response = await UserModel.findOne({
        email: email,
    });

    if(!response)
    {
        res.json({
            message : "User doesnot exists"
        })
        return
    }
    const passwordMatch = await bcrypt.compare(password, response.password); // brcrypt itself from the hashed password can findout ,the salt and the number of rounds and will verify if the passwords match or not!!

    if (passwordMatch) {
        const token = jwt.sign({
            id: response._id.toString()
        }, JWT_SECRET);

        res.json({
            token
        })
    } else {
        res.status(403).json({
            message: "Incorrect creds"
        })
    }
});


app.post("/todo", auth, async function(req, res) {
    const userId = req.userId;
    const title = req.body.title;
    const done = req.body.done;

    await TodoModel.create({
        userId,
        title,
        done
    });

    res.json({
        message: "Todo created"
    })
});


app.get("/todos", auth, async function(req, res) {
    const userId = req.userId;

    const todos = await TodoModel.find({
        userId
    });
 
    res.json({
        todos
    })
});

app.listen(3000);