import express from 'express';
import bcrypt from 'bcrypt';
import cors from 'cors';
import joi from 'joi';
import dayjs from "dayjs";
import { v4 as uuid } from 'uuid';

import dotenv from 'dotenv';
import { MongoClient } from "mongodb";
dotenv.config();

const server = express();
server.use(express.json());
server.use(cors());

const mongoClient = new MongoClient(process.env.MONGO_URI)

let db;

mongoClient.connect().then(() => {
    db = mongoClient.db("test")
})

const signUpSchema = joi.object({
    name: joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required(),
    email: joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }),
    password: joi.string()
    .pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
    repeat_password: joi.ref('password'),
    
}).xor('password', 'access_token')
.with('password', 'repeat_password');

const loginSchema = joi.object({
    email: joi.string().email().required(),
    password: joi.required()
})

// CADASTRAR

server.post("/cadastro", async (req, res) => {
    const { name, email, password, repeat_password } = req.body;

    const passwordHash = bcrypt.hashSync(password, 10)

    const validation = signUpSchema.validate({name, email, password, repeat_password}, {abortEarly: true})

    if (validation.error) {
        console.log(validation.error.details)
        res.status(422).send(validation.error)
    }

    try {

        const validate = await db.collection('cadastro').find({email: email}).toArray()

        if( validate.length === 0) {
            const response = await db.collection('cadastro').insertOne({ name, email, password: passwordHash })

            res.status(201).send("OK")
        } else {
            res.status(409).send("usuário já cadastrado")
        }

    } catch (error) {
        res.status(422).send(error)
    }
})

// LOGAR

server.post("/login", async (req, res) => {
    const { email, password } = req.body

    const validation = loginSchema.validate({email, password}, {abortEarly: true})

    if (validation.error) {
        console.log(validation.error.details)
        res.status(422).send(validation.error)
    }

    try {
        
        const user = await db.collection('cadastro').find({ email: email }).toArray()

        const passwordIsValid = bcrypt.compareSync(password, user[0].password)

        if( user && passwordIsValid ) {
            const token = uuid();
            await db.collection('sessions').insertOne({ userId: user[0]._id, token })

            res.status(201).send({name:user[0].name, email, token})
        } else {
            res.status(409).send("usuário não encontrado")
        }

    } catch (error) {
        res.status(422).send(error)
      
    }

})

// PEGAR REGISTRO DE TRANSIÇÕES

server.get("/main-page", async (req, res) => {
    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');
  
    if(!token) return res.sendStatus(401);

    const resposta = await db.collection("sessions").findOne({ token })

    try {
        const response = await db.collection('registros').find({ userId: resposta.userId }).toArray();
    
        res.status(201).send(response)
    } catch (error) {
        res.status(422).send("Não foi possível listar os registros")
    }
})

// ADICIONAR ENTRADA

server.post("/main-page/entrada", async (req, res) => { const { value, description } = req.body;
     const { authorization } = req.headers;
     const token = authorization?.replace('Bearer ', '');

     if(!token) return res.sendStatus(401);

     const resposta = await db.collection('sessions').findOne({ token })   

    try {

        const response = await db.collection('registros').insertOne({
            userId: resposta.userId,
            date: dayjs().format("DD/MM"), 
            value, 
            description, 
            type: "entrada" 
        })
        
        res.status(201).send("Ok")

    } catch (error) {
        res.status(422).send(error)
    }
})

// ADICIONAR SAÍDA

server.post("/main-page/saida", async (req, res) => { const { value, description } = req.body;
    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');

    if(!token) return res.sendStatus(401);

    const resposta = await db.collection('sessions').findOne({ token })  

    try {
        const response = await db.collection('registros').insertOne({
            userId: resposta.userId,
            date: dayjs().format("DD/MM"), 
            value, 
            description, 
            type: "saida"
        })
        res.status(201).send("Ok")
    } catch (error) {
        res.status(422).send(error)
    }
})

server.listen(5000)
console.log("Ouvindo na porta 5000...")
