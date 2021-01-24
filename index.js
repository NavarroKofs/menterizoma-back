const express    = require('express');
const bodyParser = require('body-parser');
const jwt        = require("jsonwebtoken");
const mysql      = require('mysql');
const crypto     = require('sha3');
const config     = require('./configs/config');
const nodemailer = require("nodemailer");
const logger     = require('./utils/logger');

const port = 3000;

const app = express();

const protectedRoute = express.Router();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({limit:'10mb'}));

app.set('secret_key', config.CLAVE_SECRETA);

//-----------------------------------------------------------------------------

// connection configurations
var dbConn = mysql.createConnection({
    host: config,
    port:3306,
    user: 'root',
    password: 'admin',
    database: 'seguridad'
});
// connect to database
dbConn.connect();
//Home
app.get('/', (req, res) => res.send('Running node!'));

//-----------------------------------------------------------------------------

//Registro
app.post('/registry', (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    var sQuerySelect = "select iid from usuario where cusuario = '" + email +"'";
    var Acode = "";
    if((email != null && email != undefined) && (password != null && password != undefined)){
        dbConn.query(
            sQuerySelect, 
            function (error, results, fields) {
                if(error){
                    logger.error(error.message);
                    throw error;
                }//fin:if
                else{
                    if ((results.length) == 0) {
                        sQueryInsert = 'INSERT INTO usuario (cusuario, cpassword, lactivo, activationCode)';
                        sQueryInsert += 'VALUES(?, ?, ?, ?)';
                        Sha3Pass = new crypto.SHA3(512).update(password).digest('hex');
                        Acode = '{"email":"'+ email +'","password":"'+ password +'"}';
                        ShaAcode = new crypto.SHA3(512).update(Acode).digest('hex');
                        let aDataInsert = [email, Sha3Pass, 0, ShaAcode];
                        dbConn.query(sQueryInsert, aDataInsert, (err, results, fields) => {
                            if (err) {
                                logger.info(err.message);
                                throw err;
                            } else {
                                urlVerification = config.URL_BASE + "/verification?key=" + ShaAcode;
                                sendVerificationCode(email, urlVerification);
                                logger.info("/registry (POST) Se le ha mandado un correo de verificación a " + email);
                                return res.status(200).send(
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

//-----------------------------------------------------------------------------

//Verificar usuario
app.get('/verification', (req, res) => {
    var key = req.query.key;

    if(key != null && key != undefined){
        sQueryUpdate = 'UPDATE usuario SET lactivo=1, activationCode="" WHERE activationCode="' + key +'"';
        dbConn.query(sQueryUpdate, (err, results, fields) => {
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
                console.log(results);
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

//-----------------------------------------------------------------------------

//Generacion del Token JWT - Inciar sesión
app.post('/logIn', (req, res) => {
    
    var username = req.body.usuario;
    var password = req.body.password;

    var sQuerySelect = "select iid, cusuario, cpassword from usuario where lactivo = 1 "; 
    var Sha3Pass = "";
    var sQueryInsert  = 'INSERT INTO tokens_jwt(ctoken, iid_usuario, cusuario, dtfecha_expira, lactivo) ';
        sQueryInsert += " VALUES(?, ?, ?, ?, ? )";

    var tokenData = { }
    var dtExpireToken = 0;

    res.setHeader('Content-Type', 'application/json');

    if((username != null && username != undefined) && (password != null && password != undefined)){
        sQuerySelect += " and cusuario = '" + username + "'";
        dbConn.query(
            sQuerySelect, 
            function (error, results, fields) {
                if(error){
                    logger.info('/logIn (POST) ' + error.message);
                    throw error;
                }//fin:if
                else{
                    Sha3Pass = new crypto.SHA3(512).update(password).digest('hex'); 
                    console.log(Sha3Pass);
                    if(results.length > 0){
                        if(Sha3Pass == results[0].cpassword){

                            tokenData = {
                                usuario: results[0].cusuario
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
                                [token,results[0].iid, results[0].cusuario, dtExpire, 1];

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
                                cToken: token
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
            cError: "Los parámetros [usuario] y [password] son obligatorios",
            cToken: ""
        }); 
    }//fin:else
});//post()

//-----------------------------------------------------------------------------

//Retorna true si está activo el token
function tokenIsActive(token) {

    var sToken = token;

    if(!sToken){
        return false;
    };

    sToken = sToken.replace('Bearer ', '');

    try {
        jwt.verify(sToken, config.CLAVE_SECRETA, function(err, user) {
            if (err) {
                logger.info(err.message);
                return false;
            }//fin:else 
            else {
                return true;
            }//fin:else
        });
    }
    catch (ex) {
        logger.info(ex.message);
        return false;
    }   
};//fin:get()

//-----------------------------------------------------------------------------

//Ejemplo de creacion de middleware para procesar la peticiones antes de invocar los servicios
protectedRoute.use((req, res, next) => {
    
    const sToken = req.headers['token'];

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

//-----------------------------------------------------------------------------

app.get('/api/datos', isAuthorized, (req, res) => {
    
    return res.json(
        { 
            lError: false, 
            cError:"", 
            cMensaje:"Sucess"
        }
    );
});//fin:get

//-----------------------------------------------------------------------------

function isAuthorized(req, res, next) {

    console.log(req.headers['token']);

    if (req.headers['token'] !== undefined && req.headers['token'] !== null) {
        
        let sToken = req.headers['token'];
        
        //let privateKey = fs.readFileSync('./private.pem', 'utf8');        
        jwt.verify(sToken, app.get("secret_key"), { algorithm: "HS256" }, (err, user) => {
            if (err) {                  
                return res.status(401).json(
                    {                        
                        lError: true, 
                        cError:"El token de seguridad ya expiró."
                    }
                );
            }//fin:if (err)     
            return next();
        })
    }//fin:if (typeof req.headers['token'] !== undefined && req.headers['token'] == null) 
    else {        
        //res.status(500).json({ error: "Not Authorized" });
        return res.status(400).json(
            {
                lError: true,
                cError: "El token no fue enviado en la cabecera de la petición."
            }
        );
    }//fin:else
}//fin:isAuthorized

//-----------------------------------------------------------------------------

app.post('/api/demo', (req, res) => {

    var username = req.body.usuario;
    //var password = req.body.password;

    if((username != null && username != undefined) 
        //&& (password != null && password != undefined)
    ){
        getInformacionUsuario(username).then(function(oData) {
            console.log(oData);

            return res.json(oData);

        }).catch((err) => 
            setImmediate(() => { 
                throw err; 
            })
        );    
    }//fin:if
    else{
        return res.status(400).send({           
            lError: true,
            cError: "Los parámetros [usuario] y [password] son obligatorios",
            cToken: ""
        });
    }//fin:else    
});//fin:get

//-----------------------------------------------------------------------------

function getInformacionUsuario(_usuario){

    return new Promise(function(resolve, reject) {

        var oReturn = { "lError": "false", "cError": "", "iid" : 0, "cpassword": ""}
        var sQuerySelect = "select iid, cusuario, cpassword from usuario where lactivo = 1 and cusuario = ?"; 
        var Sha3Pass = "";

        var query_params = [_usuario];

        dbConn.query(sQuerySelect, query_params, function (err, rows, fields) {    
            if (err) {
                return reject(err);
            }//fin:if
            if(rows.length > 0){
                oReturn.lError = false;
                oReturn.iid = rows[0].iid;
                oReturn.cpassword = rows[0].cpassword;
            }//fin:if
            else{
                oReturn.lError = true;
                oReturn.cError = "No fue posible obtener la información del usuario";
            }//fin:else
            //resolve(rows);
            resolve(oReturn);
        });
    });
}//fin:getInformacionUsuario

//-----------------------------------------------------------------------------

// async..await is not allowed in global scope, must use a wrapper
async function sendVerificationCode(email, url) {
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
      subject: "Verification Code", // Subject line
      html: '<a href="'+ url +'" target="_blank">This is your verification code. Click Here to activate your account</a>', // html body
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

//-----------------------------------------------------------------------------

app.post('/postComment', (req, res) => {

    token = req.body.cToken;
    if(cToken != null && cToken != undefined){
        if (tokenIsActive(token)) {
            sQueryInsert = 'INSERT INTO comentarios (cusuario, cpassword, lactivo, activationCode)';
            sQueryInsert += 'VALUES(?, ?, ?, ?)';
        }
    }
});

//-----------------------------------------------------------------------------

function crawlServices(urls) {
    urlImgNotFound = "https://uploads-ssl.webflow.com/5d6ed3ec5fd0246da423f7a8/5dcc3ae6e62de1121a4aab86_no-disponible-7448e295ce0d80db8b02f2e8e09c6148ecbd626418792e792d0195e8c26851b9.png";
    urlImgNotFoundAnmo = "https://www.anmosugoi.com/wp-content/uploads/2019/10/sugoi-perfil-octubre.jpg";
    Curls = {
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

    let listaResultados = [];
    let listaBbc = [];
    let listaReforma =  [];
    let listaKudasai = [];
    let listaAnmo = [];
    let listaMusica = [];
    let listaDeportes = [];
    let numFeeds = [];

    for (let index = 0; index < urls.length; index++) {
        const httpOptions = {
          headers: new HttpHeaders({ 
            'Access-Control-Allow-Origin':'http://localhost:4200/', 'Content-Type': 'application/json'
          })
        };
        let urlName = urls[index];
        let url = Curls[urlName]["url"];
        let http = new HttpClient();
        http.get('/xml-to-json/?xml=' + url, httpOptions) //arreglar usando proxy (?)
        .toPromise()
        .then( (response) => {
          let resultado = {}
          let respuesta = [];
          switch (urlName) {
            case "bbc":
              respuesta = response["feed"].entry;
              numFeeds.push((respuesta).length);
              for (let aux = 0; aux < (respuesta).length; aux++) {
                let image = urlImgNotFound;
                try {
                  image = respuesta[aux].link['media:content']['media:thumbnail'][0]['@url'];
                } catch (error) {
                  image = urlImgNotFound;
                }
                if (image == undefined) {
                  image = urlImgNotFound;
                }
                resultado = generateResultado("bbc", respuesta[aux].title, respuesta[aux].link['@href'], image , respuesta[aux].summary);
                listaBbc.push(resultado);
              }
              break;
            case "reforma":
              respuesta = response["rss"].channel.item;
              numFeeds.push((respuesta).length);
              for (let aux = 0; aux < (respuesta).length; aux++) {
                resultado = generateResultado("reforma", respuesta[aux].title, respuesta[aux].link, respuesta[aux].enclosure, respuesta[aux].description);
                listaReforma.push(resultado);
              }
            break;
            case "kudasai":
              respuesta = response["rss"].channel.item;
              numFeeds.push((respuesta).length);
              for (let aux = 0; aux < (respuesta).length; aux++) {
                let content = respuesta[aux]['content:encoded'];
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
                listaKudasai.push(resultado);
              }
              break;
            case "anmo":
              respuesta = response["rss"].channel.item;
              numFeeds.push((respuesta).length);
              for (let aux = 0; aux < (respuesta).length; aux++) {
                resultado = generateResultado("anmosugoi", respuesta[aux].title, respuesta[aux].link, urlImgNotFoundAnmo, respuesta[aux].description);
                listaAnmo.push(resultado);
              }
              break;
            case "musica":
              respuesta = response["rss"].channel.item;
              numFeeds.push((respuesta).length);
              for (let aux = 0; aux < (respuesta).length; aux++) {
                let description = respuesta[aux].description;
                let divisor = description.split('<img align=\"left\" src=\"');
                divisor = divisor[1].split('\"/>\n');
                let imagen = eliminarHtml(divisor[0]);
                description = String(divisor[1]).trim();
                resultado = generateResultado("hoy.es", respuesta[aux].title, respuesta[aux].link, imagen, description);
                listaMusica.push(resultado);
              }
              break;
            case "deportes":
              respuesta = response["rss"].channel.item;
              numFeeds.push((respuesta).length);
              for (let aux = 0; aux < (respuesta).length; aux++) {
                let image = respuesta[aux].image;
                if (image == undefined) {
                  image = urlImgNotFound;
                }
                resultado = generateResultado("espn", respuesta[aux].title, respuesta[aux].link, image, respuesta[aux].description);
                listaDeportes.push(resultado);
              }
              break;
            default:
              break;
          }
          sleep(1000);
          if (index == (urls.length - 1)) {
            let numItems = Math.max(listaAnmo.length, listaBbc.length, listaDeportes.length, listaKudasai.length, listaMusica.length, listaReforma.length);
        
            for (let contador = 0; contador < numItems; contador++) {
              if (listaBbc[contador]) {
                listaResultados.push(listaBbc[contador])
              }
              if (listaAnmo[contador]) {
                listaResultados.push(listaAnmo[contador])
              }
              if (listaDeportes[contador]) {
                listaResultados.push(listaDeportes[contador])
              }
              if (listaKudasai[contador]) {
                listaResultados.push(listaKudasai[contador])
              }
              if (listaMusica[contador]) {
                listaResultados.push(listaMusica[contador])
              }
              if (listaReforma[contador]) {
                listaResultados.push(listaReforma[contador])
              }
            }
            return listaResultados;
          }
        }, (error) => {
          reject(error);
    });
}
}

aleatorizarResultados = (arr1) => {
    arr1.sort(function() { return Math.random() - 0.5 });
    return arr1;
}

generateResultado = (source, title, url, image, description) => {
    let resultado = {
        source: "",
        title: "",
        url: "",
        image: "",
        description: ""
}
    resultado.source = source;
    resultado.title = title;
    resultado.url = url;
    resultado.image = image;
    resultado.description = eliminarHtml(description);
    return resultado;
}

sleep = (ms) => {
    return new Promise( resolve => setTimeout(resolve, ms) );
}

function eliminarHtml(cadena) {
    return cadena.replace(/<\/?[^>]+>/gi, '');
}

//-----------------------------------------------------------------------------

app.listen(
    port, 
    () => {
        console.log(`Server listening in port ${port}!`);
        logger.info(`Server listening in port ${port}!`);
    }
);