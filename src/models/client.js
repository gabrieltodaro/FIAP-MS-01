const mongoose = require("../database/connection");

const schema = new mongoose.Schema({
    nomecompleto: String,
    nomeusuario: { type: String, require: true },
    email: { type: String, require: true },
    senha: { type: String },
    telefone: String,
    datacadastro: String
});

const Client = mongoose.model("Cliente", schema);

module.exports = Client;