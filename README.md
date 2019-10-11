Abraham Ludlam - LudlamAbraham@csu.fullerton.edu or abeludlam@gmail.com

This node.js application and server were made for local use on a Linux system, in this case Ubuntu 16.04.

Go to the directory of the folder. Install the requested libraries and packages as listed:
"npm install express"
"npm install client-sessions"
"npm install body-parser"
"npm install helmet"
"npm install xss-filters"
"npm install bleach"
"npm install http"
"npm install mariadb" or "apt-get install mariadb"
"npm install bcrypt"

Start the mysql instance and run the "createdb.sql" script to create the database if you haven't done so before.

If you currently don't have a mysql instance, you can follow the first half of the instructions in "SQLnotes.txt" to install mariadb and start a local mysql server.

Then type "sudo node bank.js" into the command line to run the server and program.
In a browser, go to "https://localhost:3000" to enter the program. 




Regarding security.
1.For credentials, the certificate and key are found in the folder "certs" which are used to encrypt the communication for https.

2.For mysql storage, login to your mariadb instance, run the "createdb.sql" script source from there to create the proper databases for login accounts and balance accounts. To prevent sql injections, prepared statements are used for every time the user is ask to input a value that can be placed in the database.

3.For salting and hashing, all newly created accounts have their passwords salted then hashed, with the salt being saved to allow logins. This is found in "/verify", with the salt being used in "/auth"

4. Data sent to the front-end is sent with XML tags and is bleached/escaped to avoid XSS attacks.

5. Content security policy ensures that the program only runs commands from the current program and from localhost.

     



EXTRA INFO: 2 Set timeouts can be found in the code, with a time of 1 second. While this are unwise to use for a browser application, I needed them as the program kept running later parts of the code without them. The first is found in the login page, so it properly makes sure that the user's credentials is verified, as before it would simply assume the user's credentials were wrong,

The second is found in registration, and allows the database files to be properly processed, as before it would simply return an empty array for the login credentials after a new account was created. 


Also ignore the old .txt files for accounts, they are no longer used in the code, and their names being passed to the SQL access functions is just leftover from the old code.
