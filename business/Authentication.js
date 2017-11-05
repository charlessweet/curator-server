//TODO: this is used solely to tell the difference between environments. probably an environment env would
//work better - you know, separation of concerns and all.
var couchdburl = (process.env.COUCHDB_SERVER || "http://localhost:5984");

var sha256 = require('js-sha256')
var couch = require('./Couch.js')
var err = require('./Error.js')
var common = require('./Common.js')
var jwt =require('jsonwebtoken')
var auth = require("./Error.js")

var jwt_secret = common.makeid();
/*
These are all async and rely on the callback pattern (jsonMessage, error, data) => {}
*/
 exports.verifyUserExists = function(userId, response, callback){
	var relativeUrl = "/facebook_users/_design/unique_users/_view/unique_users_idx?limit=1&reduce=false&startkey=%22" + userId + "%22&endkey=%22" + userId + "%22" 
	couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(common.varset(error)){
			reportError(error, "User has no existing account.", response, 401) 
		}else{
			if(data.rows.length > 0){
				getMembership(userId, response, callback) 
			}else{
				callback({"error":"User account not found."}, response, null) 
			}
		}
	}) 
}

exports.getMember = function(memberId, callback){
	let relativeUrl = "/member/" + memberId 
	couch.callCouch(relativeUrl, "GET", null, callback) 
}

exports.generatePasswordHash = function(password, passwordSalt){
	return sha256(password + passwordSalt) 
}

exports.getMemberByUsernamePassword = function(userName, pwd, response, callback){
	let relativeUrl = "/member/_design/memberships/_view/members_by_username?limit=2&reduce=false&startkey=%22" + userName + "%22&endkey=%22" + userName + "%22"
	couch.callCouch(relativeUrl, "GET", null, function(error, members){
		let providedPasswordHash = exports.generatePasswordHash(pwd, members.rows[0].value.password_salt)
		let relativeUrl = "/password/" + members.rows[0].id
		couch.callCouch(relativeUrl, "GET", null, function(error, password){
			if(common.varset(error)){
				callback({"error":"Credentials invalid."}, null)				
			}else if(password.value === providedPasswordHash){
				callback(null, members.rows[0].value)
			}else{
				callback({"error":"User account not found."}, null)
			}
		})
	})
}

 exports.determineRolesForUser = function(memberId, response, callback){
	let relativeUrl = "/authorization/_design/roles/_view/rolelist_idx?limit=10&reduce=false&startkey=%22" + memberId + "%22&endkey=%22" + memberId + "%22" 
	couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(common.varset(error)){
			callback({"error":"Could not load roles."}, null)
		}else{
			let roles = data.rows.map((x) => x.value) 
			callback(null, roles)			
		}
	})
}

exports.validateJWT = function(req, res, next) {
	//don't check for JWT on token exchange
	if(req.url === "/authenticate/facebook" || req.url === "/authenticate/basic"){
		next()
		return
	}
	let headerInfo = req.header("Authorization") 
	if(headerInfo !== undefined){
		let headerInfos = headerInfo.split(" ") 
		if(headerInfos.length > 1){
			try{
				let jwtParsed = jwt.verify(headerInfos[1], jwt_secret)
				req.jwt = jwtParsed
				next()
			}catch(e){
				console.log("Failed to validate JWT", req.url, e)
				res.end()	
			}
		}
	}
}

exports.allowCrossDomain = function(req, res, next) {
	var origin = "http://localhost:8888" 
	if(couchdburl === process.env.COUCHDB_SERVER){
		switch(req.headers.origin){
			case "https://www.biaschecker.org":
			case "https://biaschecker.org":
			case "http://biaschecker.org":
			case "http://www.biaschecker.org":
				origin = req.headers.origin 
				res.header('Strict-Transport-Security', "max-age=31536000  includeSubDomains") 
				break 
		}
	}
	res.header('Access-Control-Allow-Origin', "*") 
	res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS') 
	res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, X-BIASCHECKER-API-KEY, X-BIASCHECKER-APP-ID') 
	res.header('X-Frame-Options', 'SAMEORIGIN') 
	res.header('X-XSS-Protection', '1') 
	res.header('X-Content-Type-Options', 'nosniff') 
	// intercept OPTIONS method
	if ('OPTIONS' === req.method) {
		res.sendStatus(204) 
	} else {
		next() 
	}
}

exports.validateBiasCheckerApp = function(req,res,next){
	if((req.path === "/bookmark" || req.path.startsWith("/documentation/") || req.path === "/") && req.method === "GET"){
		next() 
	}else{
		var sharedSecret = req.header("X-BIASCHECKER-API-KEY") 	
		var appId = req.header("X-BIASCHECKER-APP-ID") 
		var relativeUrl = "/apps/_design/authorizedapp/_view/authorizedapp_idx?limit=100&reduce=false&startkey=%22" + appId + "%22&endkey=%22" + appId + "%22" 
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				res.json(error) 
			}else{
				if(data.rows.length > 0){
					if(sharedSecret === data.rows[0].value){
						console.log("Application " + appId + " allowed access.") 
						next() 
						return 
					}
				}				
			}
			console.log("Application " + appId + " un-authorized.") 
			res.sendStatus(403) 			
		}) 
	}
} 

exports.verifyToken = function(request, response, callback){
	if(request.query.biasToken === undefined){
		reportError("No biasToken was provided.", "Failed to validate token.", response, 401)
	}else{
		var relativeUrl = "/facebook_users/_design/tokens/_view/tokens_idx?limit=100&reduce=false&startkey=%22" + request.query.biasToken + "%22&endkey=%22" + request.query.biasToken + "%22"
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				reportError(error, "Failed to validate token.", response, 401)
			}else{
				//this is weird.  so there are situations in which we want to know if the token is valid, but don't want to 
				//fail automatically.  in these cases, we return data
				if(data.rows.length > 0){
					data = data.rows[0].value
				}else{
					error = { "message":"The token is invalid."}
					data = null
				}
				callback(error, response, data)
			}
		})		
	}
}

/**
You might have noticed the salt above. That is for salting the login requests, this one is the secret
for signing the jwt.
*/
exports.generateJwt = function(data){
	let expirationWindow = (Math.random() * (180 - 60) + 60) + "m";
	let token = jwt.sign(data, jwt_secret, { expiresIn : expirationWindow, issuer: "urn:curator.biascheker.org"});
	return token;
}