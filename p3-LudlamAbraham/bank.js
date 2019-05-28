// Set up global variables to keep track of wins and runs, Import the express package

"use strict"
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const express = require('express');
const sessions = require('client-sessions');
var bodyParser = require('body-parser');
const fs = require('fs');
const helmet = require('helmet');
var xssFilters = require('xss-filters');
var bleach = require('bleach');
const https = require('https');



var app = express();


var http = require('http');
var bodyParser = require("body-parser");
app.use(bodyParser.urlencoded({ extended: true })); 


//Setup the CSP to ensure that our program is only running things from the localhost and our server.
app.use(helmet.contentSecurityPolicy({
	directives: {
		defaultSrc: ["'self'"],
		scriptSrc: ["'self'", "'unsafe-inline'", "http://localhost:*"],
		styleSrc: ["'self'", "'unsafe-inline'", "http://localhost:*"]
		
		
		}
		}))

//The mysql connection to the local mysql server
var mysqlConn = mysql.createConnection({
	host: "localhost",
	user: "appaccount",
	password: "apppass",
	multipleStatements: true
	
});

//Generate a random number for the cookies to protect the sessions.
var randomNumber=Math.random().toString();
randomNumber=randomNumber.substring(2,randomNumber.length);
app.use(sessions({
  cookieName: 'session',
  secret:  randomNumber,
  duration: 3 * 60 * 1000 ,
  activeDuration: 3 * 60 * 1000,
  httpOnly: true,
  secure: true,
  ephemeral: true
})); 
 
//Generate a map to help escape html code to avoid XSS attacks.
 var map= {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
};
function escapeHTML(s, forAttribute) {
    return s.replace(forAttribute ? /[&<>'"]/g : /[&<>]/g, function(c) {
        return map[c];
    });
}

//The default page the user tries to go to. If they are logged in, they go to their dashboard, if they are not, they go to the login page.
app.get("/", function(req, resp){
		
	if(req.session.username){
	resp.sendFile(__dirname + "/dashboard.html");	
	}
	else{
	resp.sendFile(__dirname + "/login.html");	
	}
	
});

//Brr is used to store login data temporarily from the mysql server for use in the program, counts keeps track of the total number accounts.
//accs is used to store balance data temporarily for use in the program, a_counts keeps track of the total number of balance accounts.
var brr = []
var count = 0
var accs = []
var a_count = 0
var active = "";

//Access the mysql database for login data.
function processFile(inputFile) {
	count = 0
	brr = []
	mysqlConn.query("USE users; SELECT * from LoginAccounts;", function(err, qResult){
					
		if(err) throw err;
	

     	qResult[1].forEach(function(account){
     	var sma= account['username']
     	var smb= account['password']
     	var smc= account['salt']
     	var mar = [sma, smb, smc]
        brr.push(mar)
     	count = count + 1
     	});

});

}


//Access the mysql database for balance data.
function processAcc(inputFile) {
	a_count = 0
	accs = []
    mysqlConn.query("USE users; SELECT * from BalanceAccount;", function(err, qResult){
					
		if(err) throw err;
		qResult[1].forEach(function(account){
     	var sma= account['bName']
     	var smb= account['aName']
     	var smc= account['amount']
     	
       
        var mat = [sma, smb, smc]
        accs.push(mat)
      
        a_count = a_count + 1
        });
    });
    
   
}
processFile('pass.txt');

//For the "login.html" page. Check to see if the login credentials the user inputted are correct.
app.post("/auth", function(req, resp){
	
	var found = 0

	var pChoice = bleach.sanitize(req.body.username);
	var pas = bleach.sanitize(req.body.password);
	
   	var momt = '';		 
   	
	for(let iterate = 0;  iterate < count; iterate++){
		
			if(pChoice.toLowerCase() === brr[iterate][0].toLowerCase()){
			bcrypt.hash(pas, brr[iterate][2], function(err, hash) {
				
				momt = brr[iterate][1];	
				
				if(hash === momt){
					found = 1;
					
					}
					else{
					
					}
					});
			}
			else{
			
			
		
		
		}
	
	}
	
		
	var respString = ""
	setTimeout(function(){
	if(found === 1){
		respString += "Logined Successfully" ;
		req.session.username = pChoice;
		active = pChoice;
		resp.redirect('/dashboard');
		
	}
	else{
		respString += "Wrong Username or Password" ;
		resp.send(respString);
	}
	}, 1000);
	
	
	
	
});

//Function that helps escape symbols for when data is received from HTML page to avoid security risks.
function jEscape(Data)
{
     
    
    var escaped = ""
     
    var charCode = null;
     
   
    var character = null
     
    // Go through the entire string and replace each 
    // character <255 with \xHH
    for(let index = 0; index < Data.length; ++index)
    {
        // The character
        charCode = Data.charCodeAt(index);
         
        // The character
        character = Data.charAt(index);    
         
        // Is this is a numerical character?
        var isNum = ((charCode <= 57 && charCode >= 48) || (charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122));
         
        // Should we escape?
        if(charCode < 255 && !(isNum))
            // Escape 
            character =  "\\x" + charCode.toString(16);
         
        // Add to the string
        escaped += character
    }
     
    // Enclose the string in single quotes
    // so the front-end knows how to interpret it
    //console.log(escaped);
    return escaped;
}

//Send the user to their dashboard once logged in.
app.get("/dashboard", function(req, res){
	if(req.session.username){
	res.sendFile(__dirname + "/dashboard.html");	
	}
	else{
	res.redirect('/');
	}

});

//Associeated with "dashboards.html". Send the login account name to display it on the page.
app.post('/accounts', function(req, res){
 
    res.send("<account>" + xssFilters.inHTMLData(bleach.sanitize(req.session.username)) +"</account>");    
});

//bchosen is used to keep track of the chosen balance name the user chooses.
var bchosen = ""

//Associated with "balance.html". Send balance account to the balance page for use there.
app.post('/aname', function(req, res){
 
    res.send("<account>" + xssFilters.inHTMLData(bchosen) +"</account>");    
});


app.post('/somet', function(req, res){
 
    res.send("<account>" + xssFilters.inHTMLData(bchosen) +"</account>");    
});

//Associated with "dashboard.html". Go to the balance page for the chosen balance account.
app.post('/iacc', function(req, resp){
 	var respstring = "";
 	bchosen = bchosen.replace(bchosen, "")
 
 	bchosen= bchosen + (req.body.chosen)
 	
 	if(req.session.username){
	resp.sendFile(__dirname + "/balance.html");	
	}
	else{
	resp.redirect('/');
	}
    
});

//Associated with "balance.html". Generate a list of balance accounts that belong to the login account and are not the current balance account.
app.post('/notthis', function(req, res){
    var iterate3 = 0;
    var lis = "";
    while(iterate3 < a_count){
    	if(accs[iterate3][1].toLowerCase() === req.session.username.toLowerCase() && !(accs[iterate3][0] === bchosen))
    	{
			lis += "<option value=\"" + jEscape(xssFilters.inHTMLData(accs[iterate3][0])) + "\">" + jEscape(xssFilters.inHTMLData(accs[iterate3][0])) + "</option>";
		}
		iterate3 += 1
	}
    res.send("<lis>" + lis + "</lis>");    
});

//Associated with "balance.html". Display the total amount of money associated with the balance account.
app.post('/currentBalance', function(req, res){
    var iterate4 = 0;
    var liste = "";
    while(iterate4 < a_count){
    	if(accs[iterate4][1].toLowerCase() === req.session.username.toLowerCase() && (accs[iterate4][0] === bchosen))
    	{
			liste += "<balance>" + accs[iterate4][2] + "</balance>";
		}
		iterate4 += 1
	}
    res.send(liste);    
});

//Associated with "dashboard.html". Generate a list of balance accounts associated with the login account.
app.post('/caccs', function(req, res){
    var iterate2 = 0;
    var lis = "";
    while(iterate2 < a_count){
    	if(accs[iterate2][1].toLowerCase() === req.session.username.toLowerCase())
    	{
			lis += "<option value= \"" + jEscape(xssFilters.inHTMLData(accs[iterate2][0])) + "\">" + jEscape(xssFilters.inHTMLData(accs[iterate2][0])) + "</option>";
		}
		iterate2 += 1
	}
    res.send("<lis>" + lis + "</lis>");    
});

//Associated with "balance.html". Withdraw money from the current balance account
app.post('/withdraw', function(req, resp){
    var iterate5 = 0;
    var respString = "";
    var lis = "";
    var vert = 0;
    var withd = bleach.sanitize(req.body.witha)
    if(withd < 0)
    {
    	withd=0;
    }
    while(iterate5 < a_count){
    	if(accs[iterate5][1].toLowerCase() === req.session.username.toLowerCase() && (accs[iterate5][0] === bchosen))
    	{
    		if(Number(withd)<=Number(accs[iterate5][2])){
    		accs[iterate5][2]=Number(accs[iterate5][2])
			accs[iterate5][2] -= Number(withd)
			mysqlConn.query("USE users; UPDATE BalanceAccount SET amount = ?  where  bName= ? AND aName= ?;", [accs[iterate5][2],accs[iterate5][0],accs[iterate5][1]], function(err, qResult){
   			 if(err) throw err;
   			 
   			 });
			vert = 1;
			}
			else{
			respString += "Withdrawal amount is larger than balance";
			var hls = "<br> Click here to go back to account balance management";
			var res = hls.link("/balance");
			respString += res;
			resp.send(respString)
			}
		}
		iterate5 += 1
	}
	if(vert){
	
	processAcc('accounts.txt');
    resp.sendFile(__dirname + "/balance.html");	
    }   
});

//Associated with "balance.html". Transfer money from the current account to the chosen account 
app.post('/transfer', function(req, resp){
    var iterate5 = 0;
    var respString = "";
    var lis = "";
    var vert = 0;
    var otheracc = bleach.sanitize(req.body.chosen)
    var trans = bleach.sanitize(req.body.trans)
    if (trans < 0)
    {
    
   		trans=0;
    }
    while(iterate5 < a_count){
    	if(accs[iterate5][1].toLowerCase() === req.session.username.toLowerCase() && (accs[iterate5][0] === bchosen))
    	{
    		if(Number(trans)<=Number(accs[iterate5][2])){
    		accs[iterate5][2]=Number(accs[iterate5][2])
			accs[iterate5][2] -= Number(trans)
			mysqlConn.query("USE users; UPDATE BalanceAccount SET amount = ?  where  bName= ? AND aName= ?;", [accs[iterate5][2],accs[iterate5][0],accs[iterate5][1]], function(err, qResult){
   			 if(err) throw err;
   			 
   			 });
			vert = 1;
			}
			else{
			respString += "Withdrawal amount is larger than balance";
			var hls = "<br> Click here to go back to account balance management";
			var res = hls.link("/balance");
			respString += res;
			resp.send(respString)
			}
		}
		iterate5 += 1
	}
	if(vert){
	iterate5=0;
	while(iterate5 < a_count){
	if(accs[iterate5][1].toLowerCase() === req.session.username.toLowerCase() && (accs[iterate5][0] === otheracc.toLowerCase()))
    	{
    		
    		accs[iterate5][2]=Number(accs[iterate5][2])
			accs[iterate5][2] += Number(trans)
			mysqlConn.query("USE users; UPDATE BalanceAccount SET amount = ?  where  bName= ? AND aName= ?;", [accs[iterate5][2],accs[iterate5][0],accs[iterate5][1]], function(err, qResult){
   			 if(err) throw err;
   			 
   			 });
			
		}
		iterate5 += 1
	}
	
	processAcc('accounts.txt');
    resp.sendFile(__dirname + "/balance.html");	
    }   
});

//Send the user to the chosen balance page.
app.get('/balance', function(req, res)
{
	if(req.session.username){
	res.sendFile(__dirname + "/balance.html");		
	}
	else{
	resp.sendFile(__dirname + "/login.html");	
	}

});

//Associated with "balance.html". Deposit money into the current balance account.
app.post('/deposit', function(req, res){
    var iterate5 = 0;
    var lis = "";
    var depos = bleach.sanitize(req.body.depo)
    while(iterate5 < a_count){
    	if(accs[iterate5][1].toLowerCase() === req.session.username.toLowerCase() && (accs[iterate5][0] === bchosen))
    	{
    		accs[iterate5][2]=Number(accs[iterate5][2])
			accs[iterate5][2] += Number(depos)
			mysqlConn.query("USE users; UPDATE BalanceAccount SET amount = ?  where  bName= ? AND aName= ?;", [accs[iterate5][2],accs[iterate5][0],accs[iterate5][1]], function(err, qResult){
   			 if(err) throw err;
   			 
   			 });
		}
		iterate5 += 1
	}
	
	processAcc('accounts.txt');
    res.sendFile(__dirname + "/balance.html");	    
});

//Send the user to the register page
app.get("/register", function(req, resp){
		
	
	resp.sendFile(__dirname + "/register.html");	
	
});

//Associated with "register.html". Verify that the account the user is trying to create doesn't match another users, and if so, add the account to the database.
app.post("/verify", function(req, resp){
	
	var respString = "";
	var usename = bleach.sanitize(req.body.username);
	var passw = bleach.sanitize(req.body.psw);
	var ver = 0;
	var iterate = 0
	

	while(ver === 0 && iterate < count){
		
			if(usename.toLowerCase() === brr[iterate][0].toLowerCase()){
				ver = 1
			}
			
		
		iterate += 1
	}
	if(ver === 1){
	respString += "Username is taken";
	var hls = "<br> Click here to go back to registration";
	var res = hls.link("/register");
	respString += res;
	}
	else{
	respString += "Successfully Registered";
	var hls = "<br> Click here to go to the login page";
	var res = hls.link("/");
	respString += res;
	bcrypt.genSalt(10, function(err, salt) {
   			 bcrypt.hash(passw, salt, function(err, hash) {
   			 mysqlConn.query("USE users; INSERT INTO LoginAccounts VALUES ( ?, ?, ?);", [usename, hash, salt], function(err, qResult){
   			 if(err) throw err;
   			 //console.log(qResult[1]);	
   			 
   			 });
   			 });
   			 });
	
	
	setTimeout(function(){processFile('pass.txt');}, 1000);
	
	}
	
	resp.send(respString);
});

processAcc('accounts.txt');

//Associated with "dashboard.html". Logout the user and resets the session key for the user.
app.get('/logout', function(req, res) {
  req.session.reset();
  res.redirect('/');
});

//Associated with "dashboard.html". Allows a user to create a new balance account for their bank account.
app.post("/newacc", function(req, resp){
	//processAcc('accounts.txt');
	var respString = "";
	var accountName = bleach.sanitize(req.body.acc);
	var ver = 0;
	var iterate = 0
	//brr.forEach(function(v) {if(usename.toLowerCase() === brr[v][0].toLowerCase()){ ver = 1}});

	while(ver === 0 && iterate < a_count){
		
			if(accountName.toLowerCase() === accs[iterate][0].toLowerCase()&& active.toLowerCase() === accs[iterate][1].toLowerCase()){
				ver = 1
			}
			
		
		iterate += 1
	}
	if(ver === 1){
	respString += "Account name already used";
	var hls = "<br> Click here to go to dashboard";
	var res = hls.link("/dashboard");
	respString += res;
	resp.send(respString);
	
	}
	else{
	respString += "Account created";
	var hls = "<br> Click here to go to dashboard";
	var res = hls.link("/dashboard");
	respString += res;
	
	mysqlConn.query("USE users; INSERT INTO BalanceAccount VALUES ( ?, ?, ?);", [accountName, active, 0], function(err, qResult){
   			 if(err) throw err;
   			 //console.log(qResult[1]);	
   			 
   			 });
   			
	processAcc('accounts.txt');
	resp.send(respString);
	}
	
	

});

//Function to escape data going to the frontend to prevent XSS attacks
function hEscape(Data)
{
     
    
    var escaped = ""
     
    var charCode = null;
     
   
    var character = null
     
    // Go through the entire string and replace each 
    // character <255 with \xHH
    for(let index = 0; index < Data.length; ++index)
    {
        // The character
        charCode = Data.charCodeAt(index);
         
        // The character
        character = Data.charAt(index);    
         
        // Is this is a numerical character?
        var isNum = ((charCode <= 57 && charCode >= 48) || (charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122));
         
        // Should we escape?
        if(charCode < 255 && !(isNum))
            // Escape 
            character =  "&#xHH" + charCode.toString(16);
         
        // Add to the string
        escaped += character
    }
     
    // Enclose the string in single quotes
    // so the front-end knows how to interpret it
    //console.log(escaped);
    return escaped;
}

//Create the local https server on port 3000. "localhost:3000"
https.createServer({
	key: fs.readFileSync('./certs/MyKey.key'),
	
	cert: fs.readFileSync('./certs/MyCertificate.crt')}, app).listen(3000);
//app.listen(3000);
