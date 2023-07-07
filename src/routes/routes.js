const express = require("express");
const bcrypt = require("bcrypt");
const generateToken = require("../utils/generateToken");
const verifyToken = require("../middleware/verifyToken");
const Client = require("../models/client");
const config = require("../config/settings");

const router = express.Router();

router.get("/", (req, res) => {
    Client.find()
    .select("-senha")
    .then((result) => {
        res.status(200).send({ output: "Ok", payload: result });
    }).catch((error) => {
        res.status(500).send({ output: "There's an issue here -> ${error}" });
    });
});

router.post("/insert", (req, res) => {
    const email = req.body.email;

    Client.findOne({email:email}).then((result) => {
        if(result){
            return res.status(400).send({ output: "E-mail already in use. Choose a different one."});
        }
        bcrypt.hash(req.body.senha,config.bcrypt_salt, (err, result) => {
            if(err) {
                return res.status(500).send({output: "We couldn't generate the password. -> ${err}"});
            }
        
            req.body.senha = result;
    
            const dados = new Client(req.body);
            dados.save().then((result) => {
                res.status(201).send({ output: `Cadastro realizado`, payload: result });
            }).catch((erro) => {
                res.status(500).send({ output: `Erro ao cadastrar -> ${erro}` });
            });
        });
    });
});

router.put("/update/:id", verifyToken,(req, res) => {
    Client.findByIdAndUpdate(req.params.id, req.body, {new:true}).then((result) => {
        if(!result){
            return res.status(400).send({ output: `Couldn't update.` });
        }
        res.status(202).send({ output: "Updated", payload:result });
    }).catch((erro) => {
        res.status(500).send({ output: `Erro ao processar a solicitação -> ${erro}` });
    });
});

router.delete("/delete/:id", verifyToken,(req, res) => {
    Client.findByIdAndDelete(req.params.id).then((result) => {
        res.status(204).send({ payload:result });
    }).catch((erro) => console.log(`Erro ao tentar apagar -> ${erro}` ));
});

router.post("/login", (req,res)=>{
    const usuario = req.body.nomeusuario;
    const senha = req.body.senha;

    Client.findOne({nomeusuario:usuario}).then((result) => {
        if(!result){
            return res.status(404).send({output:`User not found.`, usuario:usuario});
        }
        bcrypt.compare(senha, result.senha).then((rs) => {
            if(!rs){
                return res.status(400).send({output:`Wrong password.`});
            }
            
            const token = generateToken(result._id, result.usuario, result.email);
            res.status(200).send({output:`Authenticated`, token:token});
        }).catch((err) => res.status(500).send({output:`Erro ao processar dados ${err}`}));
    }).catch((error)=>res.status(500).send({output:`Erro ao tentar efetuar o login ${error}`}));
});

router.post("/updatePassword/:id", verifyToken, (req, res) => {
    const senhaatual = req.body.senhaatual;
    const senhanova = req.body.senha;

    Client.findById(req.params.id).then((result)=> {
        if(!result){
            return res.status(404).send({output:`User not found.`});
        }
        bcrypt.compare(senhaatual, result.senha).then((rs) => {
            if(!rs){
                return res.status(400).send({output:`Senha atual incorreta`});
            }

            bcrypt.hash(senhanova, config.bcrypt_salt, (err, senhanovacriptografada) => {
                if(err){
                    return res.status(500).send({output: `Erro ao gerar a senha -> ${err}`});
                }

                Client.findByIdAndUpdate(req.params.id, {senha: senhanovacriptografada}, {new:true}).then((result) => {
                    if(!result){
                        return res.status(400).send({ output: `Couldn't update.` });
                    }
                    res.status(202).send({ output: `Updated`, payload:result });
                }).catch((erro) => {
                    res.status(500).send({ output: `Erro ao processar a solicitação -> ${erro}` });
                });
            });
        }).catch((err) => res.status(500).send({output:`Erro ao processar dados -> ${err}`}));
    }).catch((error)=>res.status(500).send({output:`Erro ao procurar usuario -> ${error}`}));
});

router.use((req, res) => {
    res.type("application/json");
    res.status(404).send({msg:`404 - Page Not Found`});
});

module.exports = router;