// load all the things needed
var LocalStrategy   = require('passport-local').Strategy;
const nodemailer = require("nodemailer");
// load up the user model
var mysql = require('mysql');
var bcrypt = require('bcrypt');
var dbconfig = require('./database');
var connection = mysql.createConnection(dbconfig.connection);

connection.query('USE ' + dbconfig.database);

module.exports = function(passport) {

    // passport set up; required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        connection.query("SELECT * FROM users WHERE id = ? ",[id], function(err, rows){
            done(err, rows[0]);
        });
    });

    // handles signup
    passport.use(
        'local-signup',
        new LocalStrategy({
            usernameField : 'username',
            passwordField : 'password',
            nameField : 'name',
            passReqToCallback : true
        },
        function(req, username, password, done) {
            connection.query("SELECT * FROM users WHERE username = ?",[username], function(err, rows) {
                if (err)
                    return done(err);
                if (rows.length) {
                    return done(null, false, req.flash('signupMessage', 'That username is already taken.'));
                } else {
                    console.log(req.body)
                    // if there is no user with that username then create the user

                    var newUserMysql = {
                        username: username,
                        password: bcrypt.hashSync(password, bcrypt.genSaltSync(10)),  // use the generateHash function in our user model
                        name: req.body.name
                    };

                    var insertQuery = "INSERT INTO users ( username, password, name ) values (?,?,?)";

                    connection.query(insertQuery,[newUserMysql.username, newUserMysql.password, newUserMysql.name],function(err, rows) {
                        newUserMysql.id = rows.insertId;
                        //mail setup 
                        // create reusable transport method (opens pool of SMTP connections)
                        var smtpTransport = nodemailer.createTransport({
                            service: "Gmail",
                            auth: {
                            user: "",
                            pass: ""
                            },
                            tls: {
                            rejectUnauthorized: false
                            }
                        });

                        // setup e-mail data with unicode symbols
                        var mailOptions = {
                            from: "Fred Foo ✔ <noreply@avbiosci.com>", // sender address
                            to: "", // list of receivers
                            subject: "Hello ✔", // Subject line
                            text: JSON.stringify(req.body) // html body
                        }

                        // send mail with defined transport object
                        smtpTransport.sendMail(mailOptions, function (error, response) {
                            if (error) {
                                smtpTransport.close();
                                return done(null, false, req.flash('signupMessage', 'Mail not send'));
                            } else {
                                smtpTransport.close();
                                return done(null, newUserMysql);
                            }
                        });


                        
                    });
                }
            });
        })
    );

    // handles login
    passport.use(
        'local-login',
        new LocalStrategy({
            usernameField : 'username',
            passwordField : 'password',
            passReqToCallback : true
        },
        function(req, username, password, done) {
            connection.query("SELECT * FROM users WHERE username = ?",[username], function(err, rows){
                if (err)
                    return done(err);
                if (!rows.length) {
                    return done(null, false, req.flash('loginMessage', 'No user found.'));
                }

                // if the user is found but the password is wrong
                if (!bcrypt.compareSync(password, rows[0].password))
                    return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));

                // all is well, return successful user
                return done(null, rows[0]);
            });
        })
    );
};
