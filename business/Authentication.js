var sha256 = require('js-sha256')
var couch = require('./Couch.js')
var err = require('./Error.js')
/*
These are all async and rely on the callback pattern (jsonMessage, error, data) => {}
*/
 exports.verifyUserExists = function(userId, response, callback){
	var relativeUrl = "/facebook_users/_design/unique_users/_view/unique_users_idx?limit=1&reduce=false&startkey=%22" + userId + "%22&endkey=%22" + userId + "%22" 
	couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){
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

exports.getMemberByUsernamePassword = function(userName, password, response, callback){
	let relativeUrl = "/member/_design/memberships/_view/members_by_username?limit=2&reduce=false&startkey=%22" + userName + "%22&endkey=%22" + userName + "%22"
	couch.callCouch(relativeUrl, "GET", null, function(error, member){
		let providedPasswordHash = generatePasswordHash(password, member.password_salt)
		let relativeUrl = "/password/data.memberId"
		couch.callCouch(relativeUrl, "GET", null, function(error, password){
			if(password.value === providedPasswordHash){
				callback(null, null, member)
			}else{
				callback({"error":"User account not found."}, response, null)
			}
		})
	})
}

 exports.determineRolesForUser = function(memberId, response, callback){
	let relativeUrl = "/authorization/_design/roles/_view/rolelist_idx?limit=10&reduce=false&startkey=%22" + memberId + "%22&endkey=%22" + memberId + "%22" 
	couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(handleError(error, response, "Could not add roles for user.", 400))
			return 
		let roles = data.rows.map((x) => x.value) 
		callback(null, response, roles)
	})
}

exports.validateJWT = function(req, res, next) {
	//don't check for JWT on token exchange
	if(req.url === "/tokens/exchange/facebook"){
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
			}catch(e){
				console.log("Failed to validate JWT", req.url, e)
				throw e		
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
		 couch.couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
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
		 couch.couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
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
