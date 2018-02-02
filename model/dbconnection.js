var mysql = require('mysql');

var connection = mysql.createConnection({
  host     : 'http://localhost:8080',
  user     : 'root',
  password : '',
  database : 'excelData'
});

try {
	connection.connect();
  console.log('Connected to the MYSQL database');

} catch(e) {
	console.log('Database Connetion failed:' + e);
}

module.exports = connection;
