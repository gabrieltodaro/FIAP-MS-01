const jwt = require("jsonwebtoken");
const config = require("../config/settings");

function verifyToken(req, res, next){
    const sentToken = req.headers.token;

    if(!sentToken){
        return res.status(401).send({output:"There is not token. Login."});
    }
    jwt.verify(sentToken, config.jwt_secret, (err, result) => {
        if(err){
            return res.status(500).send({output:"Interal error -> ${err}"});
        };
        req.content ={
            id:result._id,
            usuario:result.nomeusuario,
            email:result.email
        }
        return next();
    })
}

module.exports = verifyToken;