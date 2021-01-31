let chai = require('chai');
let chaiHttp = require('chai-http');
const expect = require('chai').expect;

chai.use(chaiHttp);
const url= 'http://localhost:3000';

const EMAIL = "test@hotmail.com";
const PASSWORD = "123456";
const USERNAME = "Test User";
const ID = 1;

describe('Create an account: ', () => {
    it('should create an account', (done) => {
        chai.request(url)
        .post('/api/v1/signIn')
        .send({email:"test@hotmail.com", password: "123456", username: "Test User"})
        .end( function(err,res){
            expect(res).to.have.status(201);
            expect(res['body']).to.deep.equal(
                {
                    lError: false,
                    cError: "Se le ha mandado un correo de verificación a test@hotmail.com",
                    cToken: ""
                }
            );
            done();
        });
    });
});

describe('Create an account with missing parameters: ', () => {
    it('should not create an account', (done) => {
        chai.request(url)
        .post('/api/v1/signIn')
        .send({email:"test@hotmail.com", password: "123456"})
        .end( function(err,res){
            expect(res).to.have.status(422);
            expect(res['body']).to.deep.equal(
                {
                    lError: true,
                    cError: "Unprocessable Entity",
                    cToken: ""
                }
            );
            done();
        });
    });
});

describe('Activate an account: ', () => {
    it('should activate an account', (done) => {
        chai.request(url)
        .get('/api/v1/userVerification?key=a33b112854f92765af3a264e59cb8ae319bf589ecda3dbd0d1f90c86a8cc60261c0e04da0befe458ea89d0b6af972ca0a41600ece639c31288ff8cd982fe8910')
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.deep.equal(
                {
                    lError: true,
                    cError: "Activation completed. Now you can log in.",
                    cToken: ""
                }
            );
            done();
        });
    });
});

describe('Activate an account with a not valid Email: ', () => {
    it('should not activate an account', (done) => {
        chai.request(url)
        .get('/api/v1/userVerification?key=123')
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.deep.equal(
                {
                    lError: true,
                    cError: "Invalid Code",
                    cToken: ""
                }
            );
            done();
        });
    });
});

describe('Log in with an account: ', () => {
    it('should allow access to an account ', (done) => {
        chai.request(url)
        .post('/api/v1/logIn')
        .send({email:"test@hotmail.com", password: "123456"})
        .end( function(err,res){
            expect(res).to.have.status(201);
            expect(res['body']).to.have.all.keys('lError','cError','username','id','cToken');
            expect(res['body']['lError']).to.deep.equal(false);
            expect(res['body']['cError']).to.deep.equal("");
            expect(res['body']['username']).to.deep.equal(USERNAME);
            expect(res['body']['id']).to.deep.equal(ID);
            done();
        });
    });
});

describe('Log in with an account: ', () => {
    it('should allow access to an account ', (done) => {
        chai.request(url)
        .post('/api/v1/logIn')
        .send({email:"dasob@hotmail.com", password: "123456"})
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.deep.equal(
                {
                    lError: true,
                    cError: "El usuario no se encuentra registrado.",
                    cToken: ""
                }
            );
            done();
        });
    });
});

describe('Change Password: ', () => {
    it('should inform that send a email with a password code ', (done) => {
        chai.request(url)
        .post('/api/v1/resetPassword')
        .send({email:"test@hotmail.com"})
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.deep.equal(
                {
                    lError: false,
                    cError: "An email was sent to you with your code to reset your password.",
                    cToken: ""
                }
            );
            done();
        });
    });
});

describe('Change Password with an invalid email: ', () => {
    it('should inform that the email was not found ', (done) => {
        chai.request(url)
        .post('/api/v1/resetPassword')
        .send({email:"dasob@hotmail.com"})
        .end( function(err,res){
            expect(res).to.have.status(404);
            expect(res['body']).to.deep.equal(
                {
                    lError: true,
                    cError: "This email was not found.",
                    cToken: ""
                }
            );
            done();
        });
    });
});

describe('Change Password with fake values: ', () => {
    it('should inform that the code is incorrect ', (done) => {
        chai.request(url)
        .put('/api/v1/resetPassword')
        .send({email:"test@hotmail.com", code:"123", password:"fmatuady"})
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.deep.equal(
                {
                    lError: true,
                    cError: "Invalid Code",
                    cToken: ""
                }
            );
            done();
        });
    });
});

describe('Comment into a news: ', () => {
    it('should allow create a comment in a news', (done) => {
        chai.request(url)
        .post('/api/v1/comment')
        .send({pubId:1,userId:1,comment:"UADYFMAT",usuario:"Roberto",cToken:"123456"})
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.deep.equal(
                {
                    "data": {
                        "id": 1,
                        "pubId": 1,
                        "userId": 1,
                        "author": "Roberto",
                        "comment": "UADYFMAT",
                        "isDeleted": 0,
                        "isEdited": 0
                    },
                    "lError": false,
                    "cToken": ""
                }
            );
            done();
        });
    });
});

describe('Update a comment: ', () => {
    it('should allow update a comment in a news', (done) => {
        chai.request(url)
        .put('/api/v1/comment/1')
        .set('token', '')
        .send({comment:"testchai"})
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.deep.equal(
                {
                    "data": [{
                        "id": 1,
                        "pubId": 1,
                        "userId": 1,
                        "author": "Roberto",
                        "comment": "testchai",
                        "isDeleted": 0,
                        "isEdited": 1
                    }],
                    "lError": false,
                    "cToken": ""
                }
            )
            done();
        });
    });
});

describe('Get a comment: ', () => {
    it('should allow get a comment in a news', (done) => {
        chai.request(url)
        .get('/api/v1/comment/1')
        .send({})
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.deep.equal(
                {
                    "data": [{
                        "id": 1,
                        "userId": 1,
                        "author": "Roberto",
                        "comment": "testchai",
                        "isDeleted": 0,
                        "isEdited": 1
                    }],
                    "lError": false,
                    "cToken": ""
                }
            )
            done();
        });
    });
});

describe('Delete a comment: ', () => {
    it('should allow delete a comment in a news', (done) => {
        chai.request(url)
        .delete('/api/v1/comment/1')
        .end( function(err,res){
            expect(res).to.have.status(204);
            expect(res['body']).to.deep.equal({})
            done();
        });
    });
});

describe('Get a news of an specific source: ', () => {
    it('should allow get a specific source news', (done) => {
        chai.request(url)
        .get('/api/v1/publications?source=somoskudasai')
        .end( function(err,res){
            expect(res).to.have.status(200);
            done();
        });
    });
});

describe('Get a specific news: ', () => {
    it('should allow get a specific news', (done) => {
        chai.request(url)
        .get('/api/v1/publication/1')
        .set('token', '123')
        .end( function(err,res){
            expect(res).to.have.status(200);
            expect(res['body']).to.have.all.keys('lError','data','cToken');
            done();
        });
    });
});