const express    = require('express');
const bodyParser = require('body-parser');
const jwt        = require("jsonwebtoken");
const mysql      = require('mysql');
const crypto     = require('sha3');
const config     = require('./configs/config');
const nodemailer = require("nodemailer");
const logger     = require('./utils/logger');
const axios      = require('axios');
const cron = require('node-cron');
const expressSanitizer = require('express-sanitizer');

const port = 3000;

const app = express();

const protectedRoute = express.Router();

const apiUrlBase = "/api/v1";

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({limit:'10mb'}));
app.use(expressSanitizer());

app.set('secret_key', config.CLAVE_SECRETA);

// connection configurations
var dbConn = mysql.createConnection(config.configdb);
// connect to database
dbConn.connect();

/**
* Returns a status 201 and an array indicating that an email was sent and an indicator that no error occurred.
* When an error ocurrs, return lError true and the respective status code and description.
* This route allows creating a user route.
*
* @param  email  the email with which the user is going to register
* @param  password  the password with which the user is going to register
* @param  username the username with which the user will register
* @return  returns code 201 if everything was successful or an error code and its description if something went wrong
*/
app.post('/api/v1/signIn', (req, res) => {
    let email = req.sanitize(req.body.email);
    let password = req.sanitize(req.body.password);
    let username = req.sanitize(req.body.username);

    var sQuerySelect = "select iid from usuario where email = ?";
    var Acode = "";
    if((email != null && email != undefined) && (password != null && password != undefined) && (username != null && username != undefined)){
        dbConn.query(
            sQuerySelect, [email],
            function (error, results, fields) {
                if(error){
                    logger.error(error.message);
                    throw error;
                }//fin:if
                else{
                    if ((results.length) == 0) {
                        sQueryInsert = 'INSERT INTO usuario (email, password, username, lactivo, activationCode)';
                        sQueryInsert += 'VALUES(?, ?, ?, ?, ?)';
                        Sha3Pass = new crypto.SHA3(512).update(password).digest('hex');
                        Acode = '{"email":"'+ email +'","password":"'+ password +'"}';
                        ShaAcode = new crypto.SHA3(512).update(Acode).digest('hex');
                        let aDataInsert = [email, Sha3Pass, username, 0, ShaAcode];
                        dbConn.query(sQueryInsert, aDataInsert, (err, results, fields) => {
                            if (err) {
                                logger.info(err.message);
                                throw err;
                            } else {
                                urlVerification = config.URL_BASE + apiUrlBase + "/userVerification?key=" + ShaAcode;
                                sendEmail(email, urlVerification, "This is your verification code. Click Here to activate your account", "Verification Code");
                                logger.info("/registry (POST) Se le ha mandado un correo de verificación a " + email);
                                return res.status(201).send(
                                    {
                                        lError: false,
                                        cError: "Se le ha mandado un correo de verificación a " + email,
                                        cToken: ""
                                    }
                                );
                            }
                        });
                    } else {
                        if ((results.length == 1) && (results[0].lactivo == 0)) {
                            logger.info("/registry (POST) El usuario intentó registrarse con el email " + email +" pero se había mandado un correo de verificación con anterioridad.")
                            return res.status(200).send(
                                {
                                    lError: false,
                                    cError: "Se le ha mandado un correo de verificación a " + email +" con anterioridad.",
                                    cToken: ""
                                }
                            );
                        } else {
                            logger.info("/registry (POST) El usuario intentó registrarse con el email: " + email);
                            return res.status(200).send(
                                {
                                    lError: false,
                                    cError: "El email " + email + " ya se encuentra en uso.",
                                    cToken: ""
                                }
                            );
                        }
                    }
                }
            }
        )
    } else {
        logger.info('/registry (POST) Se ingresó en la ruta con una entidad no procesable');
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }
});

/**
* Returns a status 200 and an array indicating that an email was sent and an indicator that no error occurred.
* When an error ocurrs, return lError true and the respective status code and description.
* This route sends an email with the reset code.
*
* @param  email  the email with which the user is registered in the app
* @return  returns code 200 if everything was successful or an error code and its description if something went wrong
*/
app.post('/api/v1/resetPassword', (req, res) => {
    let email = req.sanitize(req.body.email);

    if (email != null && email != undefined) {
        let sQuerySelect = 'select username from usuario where lactivo = 1 and email = ?';
        dbConn.query(
            sQuerySelect, [email],
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                if (results.length > 0) {
                    let code = Math.random() + email + Math.random() + results[0].username + Math.random();
                    let Sha3Code = crypto.SHA3(512).update(code).digest('hex');
                    sQueryUpdate = 'UPDATE usuario SET resetCode= ? where lactivo = 1 and email = ?';
                    console.log(sQueryUpdate);
                    dbConn.query(sQueryUpdate, [Sha3Code, email], (err, results, fields) => {
                        if (err) {
                            throw err;
                        }
                        sendEmail(email, "", 'This is your reset password code: ' + Sha3Code, "Reset Password");
                        return res.status(200).send(
                            {
                                lError: false,
                                cError: "An email was sent to you with your code to reset your password.",
                                cToken: ""
                            }
                        );
                    });
                } else {
                    return res.status(404).send(
                        {
                            lError: true,
                            cError: "This email was not found.",
                            cToken: ""
                        }
                    );
                }
            }
        );
    } else {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }
});

/**
* Returns a 200 status and an array indicating that the password has been updated and an indicator that no error occurred.
* When an error ocurrs, return lError true and the respective status code and description.
* This path allows changing the password of a user account .
*
* @param  email  the email with which the user is registered in the app
* @param  code  the code that was previously sent by email to reset the password
* @param  password  the new password
* @return  returns code 200 if everything was successful (and you can log in with your new credentials) or an error code and its description if something went wrong
*/
app.put('/api/v1/resetPassword', (req, res) => {
    let email = req.sanitize(req.body.email);
    let code = req.sanitize(req.body.code);
    let password = req.sanitize(req.body.password)

    if ((email != null && email != undefined) && (code != null && code != undefined)) {
        let sQuerySelect = 'select resetCode from usuario where lactivo = 1 and email = ?';
        dbConn.query(
            sQuerySelect, [email],
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                if (results.length > 0) {
                    let Sha3Pass = crypto.SHA3(512).update(password).digest('hex');
                    let sQueryUpdate = 'UPDATE usuario SET resetCode="", password= ? WHERE email= ? and resetCode = ?';
                    console.log(sQueryUpdate);
                    dbConn.query(sQueryUpdate, [Sha3Pass, email, code], (err, results, fields) => {
                        if (results.affectedRows < 1) {
                            return res.status(200).send(
                                {
                                    lError: true,
                                    cError: "Invalid Code",
                                    cToken: ""
                                }
                            );
                        } else {
                            return res.status(200).send(
                                {
                                    lError: true,
                                    cError: "Password reseted!",
                                    cToken: ""
                                }
                            );
                        }
                    });
                } else {
                    return res.status(404).send(
                        {
                            lError: true,
                            cError: "This email was not found.",
                            cToken: ""
                        }
                    );
                }
            }
        );
    } else {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }
});

/**
* Returns a 200 status and an array indicating that the account is active and an indicator that no error occurred.
* When an error ocurrs, return lError true and the respective status code and description.
* This path allows activating the previously created user account.
*
* @param  key  the key that was emailed
* @return  returns code 200 if everything was successful or an error code and its description if something went wrong
*/
app.get('/api/v1/userVerification', (req, res) => {
    var key = req.sanitize(req.query.key);

    if(key != null && key != undefined){
        sQueryUpdate = 'UPDATE usuario SET lactivo=1, activationCode="" WHERE activationCode= ?';
        dbConn.query(sQueryUpdate, [key], (err, results, fields) => {
            if (results.affectedRows < 1) {
                logger.info('/verification (GET) Se ingresó un código inválido para activar una cuenta.');
                return res.status(200).send(
                    {
                        lError: true,
                        cError: "Invalid Code",
                        cToken: ""
                    }
                );
            } else {
                logger.info('/verification (GET) Se ingresó el código' + key +' para activar una cuenta.');
                return res.status(200).send(
                    {
                        lError: true,
                        cError: "Activation completed. Now you can log in.",
                        cToken: ""
                    }
                );
            }
        });
    } else {
        logger.info('/verification (GET) Se intentó acceder en la ruta sin ingresar el parámetro key');
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }

});

/**
* Returns a 201 status and an indicator that no error occurred.
* When an error ocurrs, return lError true and the respective status code and description.
* This path allows the user to log in as long as the credentials are correct.
*
* @param  email  the email of the user registered in the app
* @param  password  the password of the user registered in the app
* @return  returns code 201 if everything was successful or an error code and its description if something went wrong
*/
app.post('/api/v1/logIn', (req, res) => {

    var email = req.sanitize(req.body.email);
    var password = req.sanitize(req.body.password);

    var sQuerySelect = "select iid, email, password, username from usuario where lactivo = 1 ";
    var Sha3Pass = "";
    var sQueryInsert  = 'INSERT INTO tokens_jwt(ctoken, iid_usuario, cusuario, dtfecha_expira, lactivo) ';
        sQueryInsert += " VALUES(?, ?, ?, ?, ? )";

    var tokenData = { }
    var dtExpireToken = 0;

    res.setHeader('Content-Type', 'application/json');

    if((email != null && email != undefined) && (password != null && password != undefined)){
        sQuerySelect += " and email = ?";
        dbConn.query(
            sQuerySelect, [email],
            function (error, results, fields) {
                if(error){
                    logger.info('/logIn (POST) ' + error.message);
                    throw error;
                }//fin:if
                else{
                    Sha3Pass = new crypto.SHA3(512).update(password).digest('hex');
                    if(results.length > 0){
                        if(Sha3Pass == results[0].password){

                            tokenData = {
                                usuario: results[0].email
                            }

                            let dtExpire = new Date();
                            dtExpire.setSeconds(dtExpire.getSeconds() + config.EXPIRE_TOKEN);
                            dtExpireToken = config.EXPIRE_TOKEN;
                            var token = jwt.sign(tokenData, config.CLAVE_SECRETA ,
                                {
                                    expiresIn:dtExpireToken
                                }
                            );

                            let aDataInsert =
                                [token,results[0].iid, results[0].email, dtExpire, 1];

                            dbConn.query(sQueryInsert, aDataInsert, (err, results, fields) => {
                                if (err) {
                                    logger.info('/logIn (POST) ' + err.message);
                                    throw err;
                                }
                            });
                            //dbConn.end();
                            logger.info('/logIn (POST) Se generó el token para (poner aquí la dirección IP).');
                            return res.status(201).send({
                                lError: false,
                                cError: "",
                                cToken: token,
                                username: results[0].username,
                                id: results[0].iid
                            });
                        }//fin:if
                        else{
                            logger.info('/logIn (POST) Se ingresó un password incorrecto desde (poner aquí la IP).');
                            return res.status(200).send(
                                {
                                    lError: true,
                                    cError: "El password es incorrecto",
                                    cToken: ""
                                }
                            );
                        }//fin:else
                    }//fin:if
                    else{
                        logger.info('/logIn (POST) Se intentó iniciar sesión con una cuenta de usuario no registrada.');
                        return res.status(200).send(
                            {
                                lError: true,
                                cError: "El usuario no se encuentra registrado.",
                                cToken: ""
                            }
                        );
                    }//fin:else
                }//fin:else
            }
        );
    }//fin:else
    else{
        logger.info('/logIn (POST) Se ingresó en la ruta con una entidad no procesable');
        return res.status(400).send({
            lError: true,
            cError: "Los parámetros [email] y [password] son obligatorios",
            cToken: ""
        });
    }//fin:else
});//post()

//-----------------------------------------------------------------------------

//Cerrar la sesión y el Token JWT
app.delete('/logOut', (req, res) => {
    var token = req.sanitize(req.body.ctoken);
    var email = req.sanitize(req.body.email);
    var sQueryDelete = 'DELETE FROM tokens_jwt where ctoken = "' + token + '" and email  = "' + email + '" LIMIT 1';
    dbConn.query(sQueryDelete, (err, results, fields) => {
        if (err) {
            logger.info('/logOut (DELETE) ' + err.message);
            throw err;
        }
        if (results['affectedRows'] > 0) {
            logger.info('/logOut (DELETE) Se ha cerrado la sesión del usuario ' + email + ".");
            return res.status(204).send(
                {
                    lError: false,
                    cError: "Se cerró la sesión correctamente.",
                    cToken: ""
                }
            );
        } else {
            logger.info('/logOut (DELETE) Se intentó cerrar una sesión cerrada de ' + email + ".");
            return res.status(200).send(
                {
                    lError: false,
                    cError: "",
                    cToken: ""
                }
            );
        }
    });
});

/**
* Verify if the token is valid. It allows access to the routes that implement it.
*
* @param  token  the token previously
* @return  return error if there is an error with status code 400.
*/
protectedRoute.use((req, res, next) => {

    const sToken = req.sanitize(req.headers['token']);
    const email = req.sanitize(req.body['email']);

    if (sToken) {
        jwt.verify(sToken, app.get('secret_key'), (err, decoded) => {
            if (err) {
                return res.json(
                    {
                        lError: true,
                        cError: "El token es invalido."
                    }
                );
            }
            else {
                req.decoded = decoded;
                
                let sQueryUpdate = 'UPDATE tokens_jwt SET ctoken = ? , dtfecha_expira = ? WHERE ctoken = ?;';

                let tokenData = {
                    usuario: email
                }
                
            
                let dtExpire = new Date();
                dtExpire.setSeconds(dtExpire.getSeconds() + config.EXPIRE_TOKEN);
                dtExpireToken = config.EXPIRE_TOKEN;
                var token = jwt.sign(tokenData, config.CLAVE_SECRETA ,
                    {
                        expiresIn:dtExpireToken
                    }
                );
            
                let aDataInsert = [token, dtExpire, sToken];
            
                dbConn.query(sQueryUpdate, aDataInsert, (err, results, fields) => {
                    if (err) {
                        logger.info(err.message);
                        throw err;
                    }
                    if (results.length == 1) {
                        return true;
                    } else {
                        return false;
                    }
                });
                next();
            }
        });
    } //fin:if
    else {
        res.status(400).send(
            {
                lError: true,
                cError: "El token no fue enviado en la cabecera de la petición."
            }
        );
    }//fin:else
});// fin:else

/**
* Allows you to send an email to a user account.
*
* @param  email  the email of the user registered in the app
* @param  url  the url that will help us execute the verification code
* @param  description  the description that we want to send in the email
* @param  subject  the subject that we will insert in the email
* @return  returns code 200 if everything was successful.
*/
async function sendEmail(email, url, description, subject) {
    let html = "";
    if (subject == 'Verification Code') {
        html = '<a href="'+ url +'" target="_blank">' + description + '</a>';
    } else {
        if (subject == 'Reset Password') {
            html = '<p>' + description + '</p>';
        }
    }

    let transporter = nodemailer.createTransport({
      host: "smtp.ethereal.email",
      port: 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: 'linnie68@ethereal.email', // generated ethereal user
        pass: 'ZNJYh8Cp7tp85jkzhB', // generated ethereal password
      },
    });

    // send mail with defined transport object
    let info = {
      from: '"MenteRizoma👻" <noReply@menteRizoma.com>', // sender address
      to: email, // list of receivers
      subject: subject, // Subject line
      html: html, // html body
    };

    transporter.sendMail(info, (error, info) => {
        if (error) {
            return res.status(500).send({
                lError: true,
                cError: error.message,
                cToken: ""
            });
        } else {
            return res.status(200).send({
                lError: true,
                cError: "Email enviado",
                cToken: ""
            });
        }
    })
    logger.info("Message sent: %s", info.messageId);
    logger.info("Preview URL: %s", nodemailer.getTestMessageUrl(info));
}

/**
* Allows the user to create a new comment entry inside an especific publication
*
* @param  pubId  id of the publication where the comment is found.
* @param  userId  id of the user that created the comment.
* @param  comment  string with the comment created.
* @param  usuario  name of the author of the comment.
* @param  cToken  token of the logged user.
* @return  returns code 200 and the information of the insert in the database.
*/
app.post('/api/v1/comment', protectedRoute, (req, res) => {
    let pubId = req.sanitize(req.body.pubId);
    let userId = req.sanitize(req.body.userId);
    let comment = req.sanitize(req.body.comment);
    let username = req.sanitize(req.body.usuario);

    if ((pubId == null || pubId == undefined) || (userId == null || userId == undefined) ||
    (comment == null || comment == undefined) || (username == null || username == undefined)) {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }

    let sQueryInsert = 'INSERT INTO comments (pubId, userId, author ,comment)';
    sQueryInsert += 'VALUES(?, ?, ?, ?)';

    let aDataInsert = [pubId, userId, username, comment];
    dbConn.query(sQueryInsert, aDataInsert, (err, results, fields) => {
        if (err) {
            logger.info(err.message);
            throw err;
        } else {
            logger.info("/api/v1/comment (POST)");
            let sQuerySelect = 'SELECT ctoken from tokens_jwt where iid_usuario = ?';

            let aDataSelect = [userId];
            dbConn.query(sQuerySelect, aDataSelect, (err, results, fields) => {
                if (err) {
                    throw err;
                }
                return res.status(200).send(
                    {
                      data:
                        {
                          id: results.insertId,
                          pubId: pubId,
                          userId: userId,
                          author: username,
                          comment: comment,
                          isEdited: 0,
                          isDeleted: 0
                        },
                        lError: false,
                        cToken: results[0].ctoken
                    }
                );
            });
        }
    });
});

/**
* Allows the user to edit an already created comment entry inside an especific publication
*
* @param  id  id of the user that edit.
* @param  userId  id of the comment to edit.
* @param  comment  string with the comment edited.
* @param  token  token of the logged user.
* @return  returns code 200 and the information of the insert in the database.
*/
app.put('/api/v1/comment/:id', protectedRoute, (req, res) => {
    let userId = req.sanitize(req.body.userId);
    let comment = req.sanitize(req.body.comment);
    let id = req.sanitize(req.params.id);
    if ((id == null || id == undefined) || (userId == null || userId == undefined) || (comment == null || comment == undefined)) {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }

    let sQueryUpdate = 'UPDATE seguridad.comments SET comment = ? , isEdited = 1 WHERE id = ?;';
    dbConn.query(sQueryUpdate, [comment, id], (err, results, fields) => {

      let sQuerySelect = "SELECT * FROM seguridad.comments where id = ? ;";
      dbConn.query(sQuerySelect, [id], (err, results, fields) => {
        let response = [];
        for (var result in results) {
          let comment = {
            id: results[result].id,
            pubId: results[result].pubId,
            userId: results[result].userId,
            author: results[result].author,
            comment: results[result].comment,
            isEdited: results[result].isEdited,
            isDeleted: results[result].isDeleted
          }
          response.push(comment);
        }
        let sQuerySelect = 'SELECT ctoken from tokens_jwt where iid_usuario = ?';

        let aDataSelect = [userId];
        dbConn.query(sQuerySelect, aDataSelect, (err, results, fields) => {
            if (err) {
                throw err;
            }
            return res.status(200).send(
                {
                    data: response,
                    lError: false,
                    cToken: results[0].ctoken
                }
            );
        });
      });
    });
  });

  /**
  * Allows the user to delete an already created comment entry inside an especific publication
  *
  * @param  id  id of the comment to delete.
  * @param  token  token of the logged user.
  * @return  returns code 204 and the information of the elimination in the database.
  */
app.delete('/api/v1/comment/:id', protectedRoute, (req, res) => {
    let userId = req.sanitize(req.body.userId);
    let id = req.sanitize(req.params.id);
    if ((id == null || id == undefined) || (userId == null || userId == undefined)) {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }
    let sQueryUpdate = 'UPDATE seguridad.comments SET isDeleted = 1 WHERE id = ? ;';
    dbConn.query(sQueryUpdate, [id], (err, results, fields) => {
      let sQuerySelect = "SELECT * FROM seguridad.comments where id = ?;"
      dbConn.query(sQuerySelect, [id], (err, results, fields) => {
        let response = [];
        for (var result in results) {
          let comment = {
            id: results[result].id,
            userId: results[result].userId,
            author: results[result].author,
            comment: results[result].comment,
            isEdited: results[result].isEdited,
            isDeleted: results[result].isDeleted
          }
          response.push(comment);
        }
        let sQuerySelect = 'SELECT ctoken from tokens_jwt where iid_usuario = ?';

        let aDataSelect = [userId];
        dbConn.query(sQuerySelect, aDataSelect, (err, results, fields) => {
            if (err) {
                throw err;
            }
            return res.status(204).send(
                {
                    data: response,
                    lError: false,
                    cToken: results[0].ctoken
                }
            );
        });
      });
    });
});

  /**
  * Allows the user to get every already created comment entry inside an especific publication
  *
  * @param  id  id of the publication which comments will be fetched.
  * @return  returns code 200 and an array with the information of every comment in the publication.
  */
app.get('/api/v1/comment/:id', (req, res) => {
    let id = req.sanitize(req.params.id);
    if (id == null || id == undefined) {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }
    let sQuerySelect = "SELECT * FROM seguridad.comments where pubId = ? ;"
    dbConn.query(sQuerySelect, [id], (err, results, fields) => {
      let response = [];
      for (var result in results) {
        let comment = {
          id: results[result].id,
          userId: results[result].userId,
          author: results[result].author,
          comment: results[result].comment,
          isEdited: results[result].isEdited,
          isDeleted: results[result].isDeleted
        }
        response.push(comment);
      }
      return res.status(200).send(
        {
            data: response,
            lError: false,
            cToken: ""
        });
    });
});

/**
* It allows to obtain the publications found in the previously
* defined links and stores them in the database
*
*/
function crawlServices() {
    const urlImgNotFound = "https://uploads-ssl.webflow.com/5d6ed3ec5fd0246da423f7a8/5dcc3ae6e62de1121a4aab86_no-disponible-7448e295ce0d80db8b02f2e8e09c6148ecbd626418792e792d0195e8c26851b9.png";
    const urlImgNotFoundAnmo = "https://www.anmosugoi.com/wp-content/uploads/2019/10/sugoi-perfil-octubre.jpg";
    const Curls = {
        bbc: {
            url: "https://www.bbc.com/mundo/ultimas_noticias/index.xml"
        },
        reforma: {
            url: "https://www.reforma.com/rss/portada.xml"
        },
        kudasai: {
            url: "https://somoskudasai.com/feed/"
        },
        anmo: {
            url: "https://www.anmosugoi.com/feed/"
        },
        musica: {
            url: "https://www.hoy.es/rss/2.0/?section=culturas/musica"
        },
        deportes: {
            url: "https://www.espn.com.mx/espn/rss/news"
        }
    }

    for (let index = 0; index < Object.keys(Curls).length; index++) {
        let urlName = Object.keys(Curls)[index];
        let url = Curls[urlName]['url'];
        axios.get('https://api.factmaven.com/xml-to-json/?xml=' + url)
        .then(function (response) {
            let resultado = {}
            let respuesta = [];
            switch (urlName) {
                case "bbc":
                respuesta = response['data']["feed"]['entry'];
                for (let aux = (respuesta).length-1; aux >= 0; aux--) {
                    let image = urlImgNotFound;
                    try {
                        image = respuesta[aux]['link']['content']['thumbnail'][0]['url'];
                    } catch (error) {
                        image = urlImgNotFound;
                    }
                    if (image == undefined) {
                        image = urlImgNotFound;
                    }
                    resultado = generateResultado("bbc", respuesta[aux].title, respuesta[aux]['link']['href'], image , respuesta[aux].summary);
                }
                break;
                case "reforma":
                respuesta = response['data']["rss"]['channel']['item'];
                for (let aux = 0; aux < (respuesta).length; aux++) {
                    resultado = generateResultado("reforma", respuesta[aux].title, respuesta[aux]['link'], respuesta[aux].enclosure, respuesta[aux].description);
                }
                break;
                case "kudasai":
                respuesta = response['data']["rss"]['channel']['item'];
                for (let aux = (respuesta).length-1; aux >= 0; aux--) {
                    let content = respuesta[aux]['encoded'];
                    let imagen = urlImgNotFound;
                    let divisor = content.split('<img loading="');
                    if (divisor[1]) {
                    divisor = divisor[1].split('src="');
                    if (divisor[1]) {
                        divisor = divisor[1].split('" ');
                    }
                    imagen = eliminarHtml(divisor[0]);
                    }
                    resultado = generateResultado("somoskudasai", respuesta[aux].title, respuesta[aux].link, imagen, respuesta[aux].description);
                }
                break;
                case "anmo":
                respuesta = response['data']["rss"]['channel']['item'];
                for (let aux = (respuesta).length-1; aux >= 0; aux--) {
                    resultado = generateResultado("anmosugoi", respuesta[aux].title, respuesta[aux].link, urlImgNotFoundAnmo, respuesta[aux].description);
                }
                break;
                case "musica":
                respuesta = response['data']["rss"]['channel']['item'];
                for (let aux = (respuesta).length-1; aux >= 0; aux--) {
                    let description = respuesta[aux].description;
                    let divisor = description.split('<img align=\"left\" src=\"');
                    divisor = divisor[1].split('\"/>\n');
                    let imagen = eliminarHtml(divisor[0]);
                    description = String(divisor[1]).trim();
                    resultado = generateResultado("hoy.es", respuesta[aux].title, respuesta[aux].link, imagen, description);
                }
                break;
                case "deportes":
                respuesta = response['data']["rss"]['channel']['item'];
                for (let aux = (respuesta).length-1; aux >= 0; aux--) {
                    let image = respuesta[aux].image;
                    if (image == undefined) {
                    image = urlImgNotFound;
                    }
                    resultado = generateResultado("espn", respuesta[aux].title, respuesta[aux].link, image, respuesta[aux].description);
                }
                break;
                default:
                break;
            }
            sleep(1000);
        })
        .catch(function (error) {
            console.log(error);
        });
    }
}

/**
* Generates time where the application "does nothing" so as not to saturate the API that is consumed.
*
* @param  ms  time in milliseconds
* @return  returns a promise that emulates the time the application "sleeps".
*/
var sleep = (ms) => {
    return new Promise( resolve => setTimeout(resolve, ms) );
}

/**
* Store into database the publications from a ssr feed.
*
* @param  source  source of the news
* @param  title  title of a news
* @param  url  url of the news in the feed (original url)
* @param  image  image of the news
* @param  description  principal part of the news, this describe the news
*/
var generateResultado = (source, title, url, image, description) => {
    if (url != null && url != undefined && url != "") {
        let sQuerySelect = "select name from publicacion where url = ?";
        dbConn.query(
            sQuerySelect, [url],
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                if (results.length == 0) {
                    let sQueryInsert = 'INSERT INTO publicacion (url, source, name, img, description)';
                    sQueryInsert += 'VALUES(?, ?, ?, ?, ?)';
                    let aDataInsert = [url, source, title, image, deleteEmojis(description)];
                    dbConn.query(sQueryInsert, aDataInsert, (err, results, fields) => {
                        if (err) {
                            logger.info(err.message);
                            throw err;
                        } else {
                            logger.info("/generateResultado se añadieron publicaciones a la base de datos.");
                        }
                    });
                }
            }
        );
    }
}

/**
* Delete emojis from an string
*
* @param  text  string text with emojis
* @return  returns a string text without emojis.
*/
function deleteEmojis(text) {
    return text.replace(/([\u2700-\u27BF]|[\uE000-\uF8FF]|\uD83C[\uDC00-\uDFFF]|\uD83D[\uDC00-\uDFFF]|[\u2011-\u26FF]|\uD83E[\uDD10-\uDDFF])/g, '');
}

/**
* Delete HTML tags from an string
*
* @param  cadena  string text with html tags
* @return  returns a string text without html tags.
*/
function eliminarHtml(cadena) {
    return cadena.replace(/<\/?[^>]+>/gi, '');
}

/**
* Get the last hunded news of a specific source
*
* @param  source  the specific source that want to get
* @return  returns the data of the specific source (if exist) and status code 200.
*/
app.get('/api/v1/publications', (req, res) => {
    let resultados = [];
    let source = req.sanitize(req.query.source);
    if (source != undefined && source != null) {
        var sQuerySelect = "select * from publicacion where source = ? ORDER BY id desc Limit 100";
        dbConn.query(
            sQuerySelect, [source],
            function (error, results, fields) {
                if(error){
                    logger.error(error.message);
                    throw error;
                }//fin:if
                else{
                    if ((results.length) > 0) {
                        for (let aux = 0; aux < results.length; aux++) {
                            let data = {
                                "id": results[aux].id,
                                "url": results[aux].url,
                                "source": results[aux].source,
                                "title": results[aux].name,
                                "image": results[aux].img,
                                "description": results[aux].description
                            }
                            resultados.push(data);
                        }
                        return res.status(200).send(
                            {
                                lError: false,
                                cError: "",
                                cToken: "",
                                data: resultados
                            }
                        );
                    } else {
                        return res.status(404).send(
                            {
                                lError: true,
                                cError: "No se encontraron resultados para " + source,
                                cToken: ""
                            }
                        );
                    }
                }
            }
        );
    } else {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }
});

/**
* Allows the user to fetch a publication from an especific id in the database
*
* @param  id  id of the publication that will be fetched
* @param  cToken  token of the logged user.
* @return  returns code 200 and the information of the publication of the id input.
*/
app.get('/api/v1/publication/:id', (req, res) => {
    let id = req.sanitize(req.params.id);
    if (id == null || id == undefined) {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }
    let sQuerySelect = "SELECT * FROM seguridad.publicacion where id = ? ;"
    dbConn.query(sQuerySelect, [id], (err, results, fields) => {
        if (err) {
            throw err;
        }
        let response = [];
        for (var result in results) {
            let comment = {
                id: results[result].id,
                url: results[result].url,
                source: results[result].source,
                name: results[result].name,
                img: results[result].img,
                description: results[result].description
            }
            response.push(comment);
        }
        return res.status(200).send(
            {
                data: response,
                lError: false,
                cToken:""
            }
        );
    });
});

/**
* Allows a simple news search
*
* @param  query  query to search into database
* @return  returns code 200 and the information of publications.
*/
app.get('/api/v1/search', (req, res) => {
    let query = req.sanitize(req.query.query);
    if (query == null || query == undefined) {
        return res.status(422).send(
            {
                lError: true,
                cError: "Unprocessable Entity",
                cToken: ""
            }
        );
    }
    
    var arrayDeCadenas = query.split(" ");
    let palabras = [];
    let sQuerySelect = "SELECT * from publicacion where ";
    let respuesta = [];
    for (let index = 0; index < arrayDeCadenas.length; index++) {
        if (index == (arrayDeCadenas.length-1)) {
            sQuerySelect = sQuerySelect + "name like ? ";
        } else {
            sQuerySelect = sQuerySelect + "name like ? or ";
        }
        palabras.push("%"+arrayDeCadenas[index]+"%");
    }
    sQuerySelect = sQuerySelect + "ORDER by id desc limit 100";
    dbConn.query(
        sQuerySelect, palabras,
        function (error, results, fields) {
            if (error) {
                throw error;
            }
            if (results.length < 1) {
                return res.status(404).send(
                    {
                        lError: true,
                        cError: "Not Found",
                    }
                );
            }
            for (let result = 0; result < results.length; result++) {
                let comment = {
                        id: results[result].id,
                        url: results[result].url,
                        source: results[result].source,
                        name: results[result].name,
                        img: results[result].img,
                        description: results[result].description
                    }
                respuesta.push(comment);
            }
            return res.status(200).send(
                {
                    data: respuesta,
                    lError: false,
                }
            );
        }
    );
});

/**
* Returns 404 if an undefined path is entered or that does not use the correct method
*
* @return  Returns 404 if an undefined path is entered or that does not use the correct method .
*/
app.use(function(req, res){
    res.send(404);
});

/**
* Allows you to run the crawling process every four hours 
*
*/
function cronJob() {
    cron.schedule('* * */4 * *', () => {
        crawlServices();
    });
}

/**
* Start the application and make the cron job available
*
*/
app.listen(
    port,
    () => {
        console.log(`Server listening in port ${port}!`);
        logger.info(`Server listening in port ${port}!`);
        crawlServices();
        cronJob();
    }
);
