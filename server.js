/**
 * AppID:  https://developers.facebook.com/apps/250670435348050/add/
 *
 *  This is the bit that connects to Facebook, and pulls the feed from 
 *  a single users account.  There's another bit that will vet links.
 *  Needed:
 *    1.  Login page with storage for login state.
 *    2.  
 */
var http = require("http");
var phantom = require("./phantom-relay.js");
var fs = require("fs");
var url = require("url");
var requestCall = require("request");
var queryString = require("querystring");
requestCall.maxRedirects = 5;

var async = require("async");
var bias = require("./bias.js");
var bodyParser = require('body-parser');
var path = require("path");
var express = require("express");
var app = express();
var sha256 = require('js-sha256');

var whitelist = ["www.npr.org", "www.theguardian.com", "www.washingtonpost.com", "www.kagstv.com", "data.bls.gov"];
var couchdburl = (process.env.COUCHDB_SERVER || "http://localhost:5984");
var apiKey = (process.env.COUCHDB_APIKEY || "service_user");
var apiPassword = (process.env.COUCHDB_APIPASSWORD || "nzskBUVuvY1YAbRmMBnP");
var couchauthheader = "Basic " + new Buffer(apiKey + ":" + apiPassword).toString("base64");

var fbapp_id = (process.env.FB_APP_ID || "382449245425765");
var fbapp_secret = (process.env.FB_APP_SECRET || "50d4cbbc4f431f21f806d50dbe0ed614");

var biasAlgorithmVersion = (process.env.BIAS_ALGORITHM_VERSION || "V2");

var COUCH_LOG_ENABLED = (process.env.COUCH_LOG_ENABLED || "no");
var AUTOMONITOR_LOG_ENABLED = (process.env.AUTOMONITOR_LOG_ENABLED || "yes");
var FB_POLLING_RATE = (process.env.FB_POLLING_RATE || 1000*60*5);

var jwt =require('jsonwebtoken');

function htmlEscape(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function varset(x){
	return !(x === null || x === undefined);
}

//print config info
function printConfig(){
	console.log("CouchDB URL:", couchdburl);
	console.log("Facebook AppId:", fbapp_id);
	console.log("Bias Algorithm Version (requested):",biasAlgorithmVersion);
	console.log("CouchDb Call Logging Enabled:", COUCH_LOG_ENABLED);
	console.log("PhatomJS Available:", (phantom.isReady() ? "yes" : "no"));
	console.log("Facebook Polling Rate:", FB_POLLING_RATE + " ms");
	console.log("Automonitor Log Enabled:", AUTOMONITOR_LOG_ENABLED);
}

printConfig();

//used to persist user within a single call
var users = []; //might want to replace with distributed key-value system eventually

var allowCrossDomain = function(req, res, next) {
	var origin = "http://localhost:8888";
	if(couchdburl === process.env.COUCHDB_SERVER){
		switch(req.headers.origin){
			case "https://www.biaschecker.org":
			case "https://biaschecker.org":
			case "http://biaschecker.org":
			case "http://www.biaschecker.org":
				origin = req.headers.origin;
				res.header('Strict-Transport-Security', "max-age=31536000; includeSubDomains");
				break;
		}
	}
	console.log("allowCrossDomain", origin);
	res.header('Access-Control-Allow-Origin', "*");
	res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
	res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, X-BIASCHECKER-API-KEY, X-BIASCHECKER-APP-ID');
	res.header('X-Frame-Options', 'SAMEORIGIN');
	res.header('X-XSS-Protection', '1');
	res.header('X-Content-Type-Options', 'nosniff');
	// intercept OPTIONS method
	if ('OPTIONS' === req.method) {
		res.sendStatus(204);
	} else {
		next();
	}
};

var validateJWT = function(req, res, next) {
	let headerInfo = req.header("Authorization");
	if(headerInfo !== undefined){
		let headerInfos = headerInfo.split(" ");
		if(headerInfos.length > 1){
			console.log(headerInfos[1], jwt_secret)
			try{
				let jwtParsed = jwt.verify(headerInfos[1], jwt_secret)
				console.log("jwt", jwtParsed)
			}catch(e){
				//allow token exchange to continue
				if(req.url === "/tokens/exchange/facebook"){
					next()
				}else{
					console.log(req.url, e)
					throw e		
				}
			}
		}
	}
}

function parseCouchResponse(couchData, callback, parms){
	if(!varset(couchData)){
		var err = {};
		err.message = "Variable 'data' was null or undefined in parseCouchResponse.";
		callback(err, null);		
	}else{
		var jsonCouch = couchData;
		if(typeof couchData !== "object"){
//			console.log("parseCouchResponse", couchData);
			jsonCouch = JSON.parse(couchData);
		}
		if(!varset(jsonCouch.error)){
			callback(null, jsonCouch, parms);
		}else{
			callback(jsonCouch, null);
		}		
	}
}

function callCouch(relativeUrl, method, data, callback, parms){
	//console.log(relativeUrl);
	if(COUCH_LOG_ENABLED === "yes"){
		console.error(method, relativeUrl);		
	}
	var url = couchdburl + relativeUrl;
	var request = {"url":url, "headers":{"Authorization":couchauthheader}, "method":method};
	if(varset(data)){
		request.json = data;
	}
	requestCall(request, function(error, nestedResponse, dataReturned){
		parseCouchResponse(dataReturned, callback, parms);
	});
}

var validateBiasCheckerApp = function(req,res,next){
	if((req.path === "/bookmark" || req.path.startsWith("/documentation/") || req.path === "/") && req.method === "GET"){
		next();
	}else{
		var sharedSecret = req.header("X-BIASCHECKER-API-KEY");	
		var appId = req.header("X-BIASCHECKER-APP-ID");
		var relativeUrl = "/apps/_design/authorizedapp/_view/authorizedapp_idx?limit=100&reduce=false&startkey=%22" + appId + "%22&endkey=%22" + appId + "%22";
		callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
				res.json(error);
			}else{
				if(data.rows.length > 0){
					if(sharedSecret === data.rows[0].value){
						console.log("Application " + appId + " allowed access.");
						next();
						return;
					}
				}				
			}
			console.log("Application " + appId + " un-authorized.");
			res.sendStatus(403);			
		});
	}
};

app.use(allowCrossDomain);
app.use(validateBiasCheckerApp);
app.use(validateJWT);
app.use(bodyParser.json());//json support
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies	

function scaleAlgV2(score){
	return Math.round(score * 100);
}

function scale(score){
	if(score < 0.005){
		return 1;
	}
	if(score < 0.01){
		return 2;
	}
	if(score < 0.0125) {
		return 3;
	}
	if(score < 0.015) {
		return 4;
	}
	if(score < 0.0175) {
		return 6;
	}
	if(score < 0.02) {
		return 7;
	}
	if(score < 0.0225) {
		return 8;
	}
	if(score < 0.025) {
		return 9;
	}
	return 10;
}

function makeid(length)
{
	if(!varset(length)){
		length = 5;		
	}
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for( var i=0; i < length; i++ ){
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}
var salt = makeid();//once per application load

function reportError(error, message, response, statusCode){
	if(!varset(statusCode)){
		statusCode = 400;
	}
	if(response !== undefined){
		try{
			response.status(statusCode)
			response.json({"message":message});		
		}catch(e){
			let stack = {}
			addToStackTrace(stack)
			console.log(e, stack, response, statusCode, message)
		}
	}
}

function handleError(error, response, failureMessage, failureHttpCode){
	if(varset(error)){
		reportError(error, failureMessage, response, failureHttpCode);
		return true;
	}
	return false;
}

function verifyToken(request, response, callback){
	if(request.query.biasToken === undefined){
		reportError("No biasToken was provided.", "Failed to validate token.", response, 401);
	}else{
		var relativeUrl = "/facebook_users/_design/tokens/_view/tokens_idx?limit=100&reduce=false&startkey=%22" + request.query.biasToken + "%22&endkey=%22" + request.query.biasToken + "%22";
		callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to validate token.", response, 401);
			}else{
				//this is weird.  so there are situations in which we want to know if the token is valid, but don't want to 
				//fail automatically.  in these cases, we return data
				if(data.rows.length > 0){
					data = data.rows[0].value;
				}else{
					error = { "message":"The token is invalid."}
					data = null
				}
				callback(error, response, data);
			}
		});		
	}
}

var allowedAccounts = 100;
function verifyAccountsAreAvailable(response, callback){
	var relativeUrl = "/facebook_users/_design/unique_users/_view/unique_users_idx?limit=100&reduce=true&group=true";
	callCouch(relativeUrl, "GET", null, function(error,data){
		if(varset(error)){
			reportError(error, "Failed to retrieve estimated available accounts.", response, 401);					
		}else{
			var parsedRows = (varset(data.rows) ? data.rows : []);
			var allowed = {};
			allowed.remaining = allowedAccounts - parsedRows.length;
			if(allowed.remaining > 0){
				callback(null, response, {"accountsAvailable":true});
			}else{
				callback({"accountsAvailable":false}, response, null);
			}
		}
	});
}

function getMembership(userId, response, callback){
	var relativeUrl ="/member/_design/memberships/_view/memberships_idx?limit=100&reduce=false&startkey=%22" + userId + "%22&endkey=%22" + userId + "%22";
	var found = {"found":true};
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){
			reportError(error, "Failed to find membership for " + userId + ".");//bad, but not critical - treat user as non-member
			callback(error, response, found);
		}else{
			if(data.rows.length > 0){
				found.memberId = data.rows[0].value;
			}
			callback(error, response, found);
		}
	});
}

function verifyUserExists(userId, response, callback){
	var relativeUrl = "/facebook_users/_design/unique_users/_view/unique_users_idx?limit=1&reduce=false&startkey=%22" + userId + "%22&endkey=%22" + userId + "%22";
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){
			reportError(error, "User has no existing account.", response, 401);
		}else{
			if(data.rows.length > 0){
				getMembership(userId, response, callback);
			}else{
				callback({"error":"User account not found."}, response, null);
			}
		}
	});
}

function getSettingsForUser(userId, callback){
	var relativeUrl = "/user_settings/" + userId;
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){
			callback(error, null);
		}else{
			callback(null, data);
		}
	});
}

function updateUserSettings(settings, callback){
	var id = settings.userId;
	var relativeUrl = "/user_settings/" + id;
	callCouch(relativeUrl, "PUT", settings, function(error, data){
		if(varset(error)){
			if(error.reason === "Document update conflict."){
				callCouch(relativeUrl, "GET", null, function(error2,data2){
					if(varset(error2)){
						callback(error2, null);
					}else{
						settings._rev = data2._rev;
						settings._id = id;
						updateUserSettings(settings, callback);
					}
				});
			}else{
				callback(error, null);
			}
		}else{
			callback(null, settings);
		}
	});	
}

function updateSiteForUser(requestingUserId, bias, response){
	var id = new Buffer(bias.link).toString("base64") + "_" + requestingUserId;
	bias.userId = requestingUserId;
	var relativeUrl = "/my_site_biases/" + id;
	callCouch(relativeUrl, "PUT", bias, function(error, data){
		if(varset(error)){
			if(error.reason === "Document update conflict."){
				callCouch(relativeUrl, "GET", null, function(error,data){
					if(varset(error)){
						reportError(error, "Failed to retrieve site bias for update.", response);
					}else{
						var bias2 = data;
						bias2.myScore = bias.myScore;
						updateSiteForUser(requestingUserId, bias2, response);						
					}
				});
			}else{
				reportError(error, "Failed to save site estimate.", response);
			}
		}else{
			response.json(bias);
		}
	});	
}

function addToStackTrace(error, callerName){
	if(!varset(error.stack)){
		error.stack = [];
	}
	error.stack.push(callerName);
}

function addSiteForUser(requestingUserId, bias, callback){
	//add to general site table
	var id = new Buffer(bias.link).toString("base64") + "_" + requestingUserId;
	bias.userId = requestingUserId;
	var relativeUrl = "/my_site_biases/" + id;
	callCouch(relativeUrl, "PUT", bias, function(error,data){
		if(varset(error)){
			addToStackTrace(error, "addSiteForUser");
			callback(error, null);
		}else{
			callback(null, data);
		}
	});
}

function addSiteToDatabase(requestingUserId, bias, callback){
	//add to general site table
	var id = new Buffer(bias.link).toString("base64");
	var relativeUrl = "/site_biases/" + id;
	callCouch(relativeUrl, "PUT", bias, function(error,data){
		if(varset(error)){
			addToStackTrace(error, "addSiteToDatabase");
			//site was already added, but possibly not for this user
			//try to add for user
			if(error.error === "conflict"){
				addSiteForUser(requestingUserId, bias, callback);				
			}else{
				callback(error, null);
			}
		}else{
			addSiteForUser(requestingUserId, bias, callback);
		}
	});
}

function addBadLink(link, callback){
	var relativeUrl = "/bad_links/" + new Buffer(link).toString("base64");
	var details = {};
	details.isBad = true;
	details.link = queryString.escape(link);//non base64 version
	details.likelyCause = "Too many redirects.";
	callCouch(relativeUrl, "PUT", details, function(error, data){
		if(varset(error)){
			if(error.error !== "conflict"){
				callback(error, null);
			}else{
				var resp = {};
				resp.link = link;
				resp.message = "Did not update because link is already tracked.";
				callback(null, resp);
			}
		}else{
			callback(null, data);
		}
	});
}

function checkKnownBadLinks(link, callback){
	var relativeUrl = "/bad_links/" + new Buffer(link).toString("base64");
	var linkInfo = {};
	linkInfo.link = link;
	linkInfo.b64link = new Buffer(link).toString("base64");
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){
			if(error.error === "not_found"){
				callback(null, linkInfo);
			}else{
				callback(error, null);				
			}
		}else{
			if(data.isBad){
				callback(data, null);
			}else{
				callback(null, linkInfo);
			}
		}
	});
}

function getTextUsingRequest(link, callback){
	var request = {"url":link, "method":"GET"};
	requestCall(request, function(err, resp, data){
		if(varset(err)){
			callback(err, null);
		}else{
			callback(null, data);
		}
	});	
}

function useAlgorithmVersion(version){
	if(!phantom.isReady){
		console.err("phantom-relay.js reports that phantom is not available or in a usable state.");
	}
	return (biasAlgorithmVersion === version && phantom.isReady);	
}



function analyzeLink(validationQuery, callback){
	let ret = {isWhiteListed:false, selfLabel:validationQuery.selfLabel, link:validationQuery.linkToValidate, biasScore:0, length:0};
	ret.title = (validationQuery.title === "" ? null : validationQuery.title);
	ret.description = (validationQuery.description === "" ? null : validationQuery.description);
	if(!varset(ret.link)){
		//do nothing
		ret.link = "Link was null or undefined.";
		callback(ret, null);
	}else{
		checkKnownBadLinks(validationQuery.linkToValidate, function(e3, data){
			if(varset(e3)){
				callback(e3, null);
				return;
			}else{
				var urlObj = url.parse(validationQuery.linkToValidate);
				if(urlObj === null || urlObj.pathname === null){
					callback({"error":"Url parsed was invalid."}, null);
					return;
				}
				if(!whitelist.find(function(element){return element === urlObj.host;})){
				  	ret.isWhiteListed = false;
			  	}else{
				  	ret.isWhiteListed = true;
			  	}
				
				var id = new Buffer(validationQuery.linkToValidate).toString("base64") + "_" + validationQuery.requestingUserId;
				var relativeUrl = "/my_site_biases/" + id;
				callCouch(relativeUrl, "GET", bias, function(error,data){
					if(varset(error)){
						if(error.error === "not_found"){
							var getText = getTextUsingRequest;
							if(useAlgorithmVersion("V2")){
								getText = phantom.extractText;
							}
							getText(ret.link, function(error, pageData){
								if(useAlgorithmVersion("V2") && !varset(ret.title)){
									if(pageData !== null){
										var idx = pageData.lastIndexOf("`") + 1;
										if(idx > 0 && idx < pageData.length){
											ret.title = htmlEscape(pageData.substring(idx));									
										}										
									}else{
										error = {"error":"No data in document."};
									}
								}
								if(!varset(ret.title)){
									var startIndex= urlObj.pathname.lastIndexOf("/");
									var title = urlObj.pathname.substring(startIndex);
									if(title.length > 25){
										title = title.substring(0, 25) + "...";
									}
									ret.title = title;
								}
								if(!varset(error)){
									   bias.checkBias(pageData, function(score, terms){
										   console.log("1 link imported: " + ret.link.substring(0, 255));
										   ret.length = pageData.length;
										   ret.biasScore = parseFloat(score);
										   //if bias score is 0 or pageData is 0 bytes then error
										   if(ret.length === 0 || ret.biasScore === 0){
											   addBadLink(ret.link, function(err,data){
												   var error = {"error":"Article was zero length or bias score was zero."};
												   callback(error, null);
											   });
											   return;											   
										   }
										   ret.data = pageData;
										   ret.algver = 2;
										   ret.scaleScore = scaleAlgV2(score);
										   ret.biasTerms = terms;
										   ret.url = urlObj;
										   ret.created = new Date();
										   ret.description = validationQuery.description;
										   console.log("adding to database")
										   addSiteToDatabase(validationQuery.requestingUserId, ret, function(error, data){
										   		console.log("in addSiteToDatabase", data.length, ret.length)
											   if(varset(error)){
											   		console.log("addSiteToDatabase error")
												   callback(error, null);  
											   }else{
											   		console.log("addSiteToDatabase result")
												   callback(null, ret);		   
											   }
										   });
									   });
								}else{
									addBadLink(ret.link, function(err, data){
										if(varset(err)){
											callback(err, null);
										}else{
											callback(data, null);//in both cases, the link was bad
										}
									});
								}
						 	});					
						}else{
							callback(error, null);//database problem
						}
					}else{
						var e2 = {};
						e2.error = "conflict";
						callback(e2, null);
					}
				});				
			}
		});
	}	
}

function verifyValidation(error, data){
	if(varset(error)){
		if(error.error !== "conflict" && !varset(error.isBad)){
			reportError(error, "Link validation failed for the reason indicated.");
		}
	}
}

function extendToken(fbAccessToken, callback){
	var url =[];
	url.push("https://graph.facebook.com/v2.8/oauth/access_token?grant_type=client_credentials");
	url.push("&client_id=");
	url.push(fbapp_id);
	url.push("&client_secret=");
	url.push(fbapp_secret);
	url.push("&fb_exchange_token=");
	url.push(fbAccessToken);
	var surl = url.join("");
	var request = {"url":surl, "method":"GET"};
	requestCall(request, function(err, resp, data){
		if(varset(err)){
			callback(err, null);
		}else{
			data = JSON.parse(data);
			callback(null, data);
		}
	});
}

function validateFeed(fbAccessToken, userId){
	var url = "https://graph.facebook.com/v2.8/" + userId + "/feed?fields=id,message,link,name,description,from&access_token=" + fbAccessToken;
	var request = {"url":url, "method":"GET"};
	requestCall(request, function(error, resp, data){
		if(AUTOMONITOR_LOG_ENABLED === "yes"){
			console.log("Validating feed for user", userId);
		}
		if(varset(error)){
			reportError(error, "Validate feed failed.");
		}else{
			var list = JSON.parse(data);
			if(!varset(list.error)){
				if(AUTOMONITOR_LOG_ENABLED === "yes"){
					console.log("Get feed succeeded.");
				}
				for(var i = 0; i < list.data.length; i++){
					var query = {};
					query.linkToValidate = list.data[i].link;
					query.title = list.data[i].name;
					query.description = list.data[i].description;
					query.requestingUserId = userId;
					if(query.linkToValidate !== null && query.linkToValidate !== undefined){
						analyzeLink(query, verifyValidation);
					}
				}			
			}else{
				reportError(list.error, "Failed to retrieve feed from Facebook.");
			}			
		}
	});
}

function validateForUnexpiredUsers(error, data, tokenData){
	if(varset(error)){
		reportError(error, "Failed to retrieve unexpired user.");					
	}else{
		if(data.rows.length > 0){
			var fbAccessToken = data.rows[0].value.accessToken;
			var ogToken = tokenData.settings.originalAccessToken;
			if(fbAccessToken !== ogToken){
				var settings = tokenData.settings;
				settings.originalAccessToken = fbAccessToken;
				extendToken(fbAccessToken, function(error, data){
					if(varset(error)){
						reportError(error, "Failed to extend the access token.");					
					}else{
						if(AUTOMONITOR_LOG_ENABLED === "yes"){
							console.log("Extended access token successfully.");
						}
						settings.longTermAccessToken = data.access_token;
						validateFeed(data.access_token, tokenData.userId);
						updateUserSettings(settings, function(error, data){
							if(varset(error)){
								reportError(error, "Failed to validate unexpired users.");
							}else{
								console.log("UPDATED TOKEN");
								console.log(data);
							}
						});
					}
				});
			}else{
				validateFeed(tokenData.settings.longTermAccessToken, tokenData.userId);				
				if(AUTOMONITOR_LOG_ENABLED === "yes"){
					console.log("Validated feed without renewing access token.");
				}
			}
		}else{
			console.log("No unexpired users available for " + tokenData.userId + ".");
			console.log("");
		}
	}
}

setInterval(function(){
  	//get list of opt-in users
	var relativeUrl = "/user_settings/_design/automonitor/_view/automonitor_idx?limit=100&reduce=false";
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){
			reportError(error, undefined, "Failed to find automonitor settings.");				
		}else{
			if(data.rows.length > 0){
				if(AUTOMONITOR_LOG_ENABLED === "yes"){
					console.log("Importing feeds for for " + data.rows.length + " users.");					
				}
				for(var i = 0; i < data.rows.length; i++){
					var facebookUserId = data.rows[i].id;
					var facebookHashedUserId = sha256(facebookUserId);
					var tokenData = {};
					tokenData.userId = facebookUserId;
					tokenData.hashedUserId = facebookHashedUserId;
					tokenData.settings = data.rows[i].value;
					if(varset(tokenData.settings)){
						relativeUrl = "/facebook_users/_design/unexpired_users/_view/unexpired_users_idx?limit=100&reduce=false&startkey=%22" + facebookHashedUserId + "%22&endkey=%22" + facebookHashedUserId + "%22";
						callCouch(relativeUrl, "GET", null, validateForUnexpiredUsers, tokenData);						
					}
				}
			}else{
				console.log("Performing no imports.");
			}
		}
	});
}, FB_POLLING_RATE); //for each user in list, validate their facebook links every 5 minutes

//determine if server is up
app.get('/ping', function(request, response){
	response.json({status:"alive"});
});

function authorized(userId, biasToken){
	return (sha256(userId + salt) === biasToken);
}

app.get('/reasoning', function(request, response){
	verifyToken(request,  response, function(error, response, data){
		if(!authorized(request.query.userID, request.query.biasToken)){
			response.status(403);
			response.json({"error":"unauthorized"});			
		}else{
			var relativeUrl ="/my_site_biases/_design/reasoning/_view/reasoning_idx?limit=100&reduce=false&startkey=%22" + request.query.link + "%22&endkey=%22" + request.query.link + "%22";
			callCouch(relativeUrl, "GET", null, function(error,data){
				var parsedRows = (varset(data.rows) ? data.rows : []);
				if(varset(error)){
					reportError(error, "Failed to retrieve estimated scores.", response);					
				}else{
					response.json(parsedRows);
				}
			});
		}
	});
});

//get articles for a user
//role:user
app.get('/users/facebook/:fbUserId/articles', function(request, response){
	verifyToken(request, response, function(error, response, data){
		if(!authorized(sha256(request.params.fbUserId), request.query.biasToken)){
			response.status(403);
			response.json({"error":"unauthorized"});
		}else{
			var relativeUrl = "/my_site_biases/_design/my_sites/_view/my_sites_idx?limit=100&reduce=false&startkey=%22" + request.params.fbUserId + "%22&endkey=%22" + request.params.fbUserId + "%22";
			console.log(".../articles", relativeUrl)
			//retrieve biases for the individual
			callCouch(relativeUrl, "GET", null, function(error, data){
				var parsedRows = (varset(data.rows) ? data.rows : []);
				if(varset(error)){
					reportError(error, "Failed to retrieve my site scores.", response);					
				}else{
					//retrieve statistics for bias
					var statUrl = "/my_site_biases/_design/my_sites/_view/avg_myscores_idx?limit=1000&reduce=true&group=true";
					//get consensus scores
					var siteStats = [];
					callCouch(statUrl, "GET", null, function(error2, data2){
						var i = 0;
						if(varset(error2)){
							console.error(error2);
						}else{
							var statsList = (varset(data2.rows) ? data2.rows : []);
							for(i = 0; i < statsList.length; i++){
								siteStats[statsList[i].key] = statsList[i].value;
							}
						}
						for(i = 0; i < parsedRows.length; i++){
							if(parsedRows[i].value.title === undefined){
								parsedRows[i].value.title = parsedRows[i].value.link;
							}
							if(varset(parsedRows[i].value.algver) && parsedRows[i].value.algver === 2){
								parsedRows[i].value.scaleScore = scaleAlgV2(parsedRows[i].value.biasScore);
							}else{
								parsedRows[i].value.scaleScore = scale(parsedRows[i].value.biasScore);
							}
							parsedRows[i].value.biasScore = parseFloat(parsedRows[i].value.biasScore);								
							if(siteStats[parsedRows[i].value.link] !== undefined){
								var stats = siteStats[parsedRows[i].value.link];
								parsedRows[i].value.consensusScore = Math.round(stats.sum/stats.count);
								parsedRows[i].value.consensusCount = stats.count;
							}				
						}
						var result = parsedRows.reverse().map((couchRow) => {
							let item = couchRow.value;
							item.id = item._id;
							delete item._id;
							delete item._rev;
							return item;
						});
						response.json(result);
					});
				}
			});
		}
	});
});

//analylize a link for bias and add to all bias articles
//role:user
app.put('/users/:userId/articles', function(request, response){
	verifyToken(request, response, function(error, response, data){
		var validatedPost = request.body;
		if(varset(validatedPost) && varset(validatedPost.userId) && !isNaN(validatedPost.myScore)){
			try
			{
				validatedPost.myScore = parseInt(validatedPost.myScore);
				updateSiteForUser(validatedPost.userId, validatedPost, response);		
			}catch(ex){
				reportError(ex, "Invalid score for user.", response);
			}
		}else{
			reportError(validatedPost, "Invalid data supplied for validation.", response);
		}
	});
});

//retrieve settings for a user
//role:user
app.get('/users/:userId/settings', function(request, response){
	verifyToken(request, response, function(error, response, data){
		getSettingsForUser(request.query.userId, function(error, data){
			if(varset(error)){
				reportError(error, data, response);
			}else{
				delete data.originalAccessToken;
				delete data.longTermAccessToken;
				response.json(data);
			}
		});
	});	
});

//add settings for a user
//role:user
app.post('/users/:userId/settings', function(request,response){
	verifyToken(request, response, function(error, response, data){
		updateUserSettings(request.body, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to save user settings.", response);
			}else{
				response.json(data);
			}
		});
	});	
});

//retrieve bookmark matching a specific id
//role:user
app.get('/bookmarks', function(request, response){
	var relativeUrl = "/bookmarks/" + request.query.id;
	if(relativeUrl === "/bookmarks/"){
		reportError(request.query, "Failed to retrieve bookmark - no id.", response);		
	}else{
		callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to retrieve bookmark.", response);				
			}else{
				delete data.rev;
				delete data.ok;
				data.id = data._id;
				delete data._id;
				delete data._rev;
				response.json(data);
			}
		});
	}
});

//create a bookmark of an article bias summary
//role:user
app.post('/bookmark', function(request,response){
	verifyToken(request, response, function(error, response, data){
		var bookmarkInfo = {};
		bookmarkInfo= request.body;
		if(bookmarkInfo._id !== undefined){
			delete bookmarkInfo._id;
			delete bookmarkInfo._rev;
			delete bookmarkInfo.isWhiteListed;
			delete bookmarkInfo.url;			
		}
		var relativeUrl = "/bookmarks/" + makeid(12);
		callCouch(relativeUrl, "PUT", bookmarkInfo, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to create bookmark.", response);				
			}else{
				delete data.rev;
				delete data.ok;
				response.json(data);
			}
		});
	});	
});

//validate a link 
//role:user
app.post('/validate', function(request, response){
	verifyToken(request, response, function(error, response, data){
		analyzeLink(request.body, function(error, data){
			if(varset(error)){
				if(error.error === "conflict"){
					reportError({"error":"Request already exists."}, "No  reason to revalidate since the request already exists.", response, 409);
				}else{
					reportError(error, "Failed to validate.", response, 400);					
				}
			}else{
				response.json(data);
			}
		});
	});	
});

app.post('/analyze', function(request, response){
	verifyToken(request, response, function(error, response, data){
		analyzeLink(request.body, (error, data)=> {
			if(varset(error)){
				if(error.error === "conflict"){
					reportError({"error":"Request already exists."}, "No  reason to revalidate since the request already exists.", response, "409");
				}else{
					reportError(error, "Failed to validate.", response, 400);					
				}
			}else{
				response.json(data);
			}
		});
	});	
});

//delete a tag from site-level article bias information
//role: philosopher-ruler
app.delete('/articles/:articleId/tags/:tag', function(request,response){
	verifyToken(request, response, function(error, response, data){
		var relativeUrl = "/site_biases/" + request.params.articleId;
		callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to retrieve article.", response);			
			}else{
				if(data.tags !== undefined){
					var tag = ";" + request.params.tag + ";";
					data.tags = data.tags.replace(tag, "");
					callCouch(relativeUrl, "PUT", data, function(error, data){
						if(varset(error)){
							reportError(error, "Failed to add tag.", response);
						}else{
							var confirm = {};
							confirm.status = "deleted";
							confirm.tag = request.params.tag;
							confirm.articleId = request.params.articleId;
							response.json(confirm);
						}
					});
				}
			}
		});
	});	
});

//get member-level article bias information
//role: owner
//TODO: finish this endpoint - should filter by userid
app.get('/users/:userId/articles/:myArticleId', function(request,response){
	var relativeUrl = "/my_site_biases/" + request.params.myArticleId;
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){
			reportError(error, "Failed to retrieve article.", response);			
		}else{
			var id = new Buffer(data.link).toString("base64");
			var parentUrl = "/site_biases/" + id;
			console.log(parentUrl);
			callCouch(parentUrl, "GET", null, function(error,data){
				if(varset(error)){
					reportError(error, "Failed to retrieve article 2.", response);					
				}else{
					var ret = {};
					ret.keywords = data.keywords;
					response.json(ret);
				}
			});
		}
	});	
});

//get all tags for a specific article
//role:user
app.get('/articles/:articleId/tags', function(request, response){
	verifyToken(request, response, function(error, response, data){
		var relativeUrl = "/site_biases/" + request.params.articleId;
		callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to retrieve article.", response);				
			}else{
				var ret = {};
				ret.tags = data.tags;
				response.json(ret);
			}
		});		
	});	
});

//adds a tag to the specified article.
//role: philosopher-ruler
app.put('/articles/:articleId/tags/:tag', function(request, response){
	verifyToken(request, response, function(error, response, data){
		var relativeUrl = "/site_biases/" + request.params.articleId;
		callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to retrieve article.", response);			
			}else{
				if(data.tags === undefined){
					data.tags = "";
				}
				var tag = ";" + request.params.tag + ";";
				var res = {};
				res.tag = request.params.tag;
				res.articleId = request.params.articleId;
				if(data.tags.indexOf(tag) === -1){
					data.tags += tag;
					callCouch(relativeUrl, "PUT", data, function(error, data){
						if(varset(error)){
							reportError(error, "Failed to add tag.", response);
							return;
						}else{
							res.status = "added";
							response.json(res);
						}
					});					
				}else{
					res.status = "present";
					response.json(res);
				}
			}
		});
	});	
});

//retrieve the list of keywords associated with an article
//role:user
app.get('/articles/:articleId/keywords', function(request, response){
	verifyToken(request, response, function(error, response, data){
		var relativeUrl = "/site_biases/" + request.params.articleId;
		callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to retrieve article.", response);				
			}else{
				var ret = {};
				ret.keywords = data.keywords;
				response.json(ret);
			}
		});		
	});	
});

//set the list of keywords associated with an article
//role: philosopher-ruler
app.put('/articles/:articleId/keywords', function(request, response){
	verifyToken(request, response, function(error, response, data){
		var keywords = request.body;
		var relativeUrl = "/site_biases/" + request.params.articleId;
		callCouch(relativeUrl, "GET", null, function(error, data){
			if(varset(error)){
				reportError(error, "Failed to retrieve article.", response);			
			}else{
				var res = {};
				res.keywords = keywords;
				res.articleId = request.params.articleId;
				data.keywords = keywords;
				callCouch(relativeUrl, "PUT", data, function(error, data){
					if(varset(error)){
						reportError(error, "Failed to add tag.", response);
						return;
					}else{
						res.status = "saved";
						response.json(res);
					}
				});					
			}
		});
	});	
});

//retrieve bias information for a specific article
//role:user
app.get('/articles/:articleId', function(request,response){
	verifyToken(request, response, function(error, response, data){
		var id = request.params.articleId;
		var relativeUrl = "/site_biases/_design/articletext/_view/articletext_idx?limit=1&reduce=false&startkey=%22" + id + "%22&endkey=%22" + id + "%22";
		//console.log(relativeUrl);
		callCouch(relativeUrl, "GET", null, function(error,data){
			if(varset(error)){
				reportError(error, "Failed to retrieve summaries.",response);
			}else{
				response.json(data);
			}
		});
	});	
});

//retrieve article summaries for all articles in the database.  if missing_tag is definied, then articles must *not* have the 
//missing tag in their keywords to show up in the returned result set
//role:user
app.get('/articles/summaries', function(request,response){
	verifyToken(request, response, function(error, response, data){
		var limit = request.query.limit;
		var tag = request.query.missing_tag;
		var relativeUrl = "/site_biases/_design/articletext/_view/articleid_idx?limit=" + limit + "&reduce=false";
		if(tag !== undefined){
			relativeUrl= "/site_biases/_design/" + tag + "_queue/_view/" + tag + "_queue_idx?limit=" + limit + "&reduce=false";
		}
		//console.log(relativeUrl);
		callCouch(relativeUrl, "GET", null, function(error,data){
			if(varset(error)){
				reportError(error, "Failed to retrieve article summaries.",response);
			}else{
				response.json(data);
			}
		});
	});	
});

app.get('/articles', function(request,response){
	verifyToken(request, response, function(error, response, data){
		var limit = (request.query.limit === undefined ? 1000 : request.query.limit)
		let relativeUrl = "/site_biases/_design/articletext/_view/article_idx?limit=" + limit + "&reduce=false"
		callCouch(relativeUrl, "GET", null, function(error,data){
			if(varset(error)){
				reportError(error, "Failed to retrieve article summaries.",response);
			}else{
				let parsedRows = data.rows
				let result = parsedRows.reverse().map((couchRow) => {
					let item = couchRow.value;
					item.id = item._id;
					delete item._id;
					delete item._rev;
					return item;
				});
				response.json(result);
			}
		});
	});	
});

//register a user with an existing facebook login to a BiasChecker login
//role: user (must be the same user)
app.post('/users/:userId/register', function(request, response){
	verifyToken(request, response, function(error, response, data){
		if(!authorized(request.params.userId, request.query.biasToken)){
			reportError("Failed to register user.", "Target and token don't match.", response, 401);			
		}else if(request.body.password === undefined || request.params.userId === undefined || 
			request.body.email === undefined){
			reportError("Failed to register user.", "No password or user id was supplied.", response);
		}else{
			verifyUserExists(request.params.userId, response, function(error, response, data){
				if(varset(error)){
					reportError(error, "Failed to register user.", response);
				}else{
					//create member object
					var member = {};
					member.userId = request.params.userId;
					member.email = request.body.email;
					member.request_guardian = request.body.guardian;
					var id = makeid(64);

					//create password object
					var password = {};
					password.value = sha256(request.body.password);

					callCouch("/password/" + id, "PUT", password, function(error, data){
						if(varset(error)){
							reportError(error,"Failed to set password for user.", response);
						}else{
							callCouch("/member/" + id, "PUT", member, function(error,data){
								if(varset(error)){
									reportError(error, "Failed to create login for member.", response);
								}else{
									var ret = {};
									ret.memberId = id;
									response.json(ret);
								}
							});
						}
					});
				}
			})
		}
	});
});

function confirmFacebookUser(authInfo, response, callback){
	let fbUrl = "https://graph.facebook.com/me?access_token=" + authInfo.accessToken;
	requestCall({url:fbUrl}, callback);	
}

function persistUser(authInfo, response, callback){
	let relativeUrl = "/facebook_users/" + authInfo.accessToken
	callCouch(relativeUrl, "PUT", authInfo, function(error, data){
		if(handleError(error, response, "Failed to save facebook user.", 400))
			return;
		confirmFacebookUser(authInfo, response, callback);
	})
}

function determineRolesForUser(memberId, response, callback){
	let relativeUrl = "/authorization/_design/roles/_view/rolelist_idx?limit=10&reduce=false&startkey=%22" + memberId + "%22&endkey=%22" + memberId + "%22";
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(handleError(error, response, "Could not add roles for user.", 400))
			return;
		let roles = data.rows.map((x) => x.value);
		callback(null, response, roles)
	})
}

//exchange a facebook token for a biasToken - checks w/facebook to determine if token is valid
//role:user
app.post('/tokens/exchange/facebook', function(request, response){
	var fbAuthToken = request.body;

	fbAuthToken.minutes = 30;
	fbAuthToken.expires = new Date(new Date().getTime() + fbAuthToken.minutes * 60000);
	fbAuthToken.userId = sha256(fbAuthToken.userID);
	fbAuthToken.biasAccessToken = sha256(fbAuthToken.userId + salt);

	delete fbAuthToken.signedRequest;
	delete fbAuthToken.userID;
	delete fbAuthToken.expiresIn;
	delete fbAuthToken.minutes;

	verifyUserExists(fbAuthToken.userId, response, function(error, response, data){
		fbAuthToken.memberId = data.memberId;
		if(varset(error)){
			verifyAccountsAreAvailable(response, function(error, response, data){
				if(handleError(error, response, "Login failed.  No accounts are available.", 400))
					return;
			});			
		}
		persistUser(fbAuthToken, response, function(error, res, data){
			if(varset(error)){
				console.log("User was persisted but failed Facebook ping.");
			}
			determineRolesForUser(fbAuthToken.memberId, response, function(error, res, rolesList){
				if(!varset(error)){
					fbAuthToken.roles = rolesList
				}
				fbAuthToken.jwt = generateJwt(fbAuthToken.userID, fbAuthToken.memberId, rolesList);
				response.json(fbAuthToken);				
			})
		})
	});
});

/**
You might have noticed the salt above. That is for salting the login requests, this one is the secret
for signing the jwt.
*/
var jwt_secret = makeid();
function generateJwt(userId, memberId, scope){
	let data = {
		"userId":userId,
		"memberId":memberId,
		"scope":scope
	}
	let expirationWindow = (Math.random() * (180 - 60) + 60) + "m";
	let token = jwt.sign(data, jwt_secret, { expiresIn : expirationWindow});
	console.log(token, jwt_secret);
	return token;
}

function isInRole(memberId, roleName, response, callback){
	let memberRole = memberId + "_" + roleName;
	var relativeUrl = "/authorization/_design/roles/_view/rolesearch_idx?limit=1&reduce=false&startkey=%22" + memberRole.toLowerCase() + "%22&endkey=%22" + memberRole + "%22";
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){ //intentional fail if user is not in role
			reportError(error, "Failed to determine user role.", response, 401);
		}else{
			if(data.rows.length > 0){
				data = data.rows[0].value;
			}else{
				data = {};
				error = { "message": "No matching role found."}
			}
			callback(error, response, data);
		}
	});		
}

app.get('/members/promotions/pending', function(request, response){
	verifyToken(request, response, function(error, response, data){
		getMembership(data.userId, response, function(error, response, data){
			isInRole(data.memberId, "Philosopher-Ruler", response, function(error, response, data){
				if(handleError(error, response, "Individual is in invalid role.", 401))
					return;
				var relativeUrl = "/member/_design/memberships/_view/unapproved_requests?limit=100&reduce=false";
				callCouch(relativeUrl, "GET", null, function(error, data){
					if(varset(error)){
						reportError(error, "Failed to determine user role.", response, 401);					
					}else{
						let rows = data.rows.map((r)=>{return {"memberId":r.value._id,"email":r.value.email, "request_guardian":r.value.request_guardian}});
						response.json(rows);
					}
				})
			})
		})
	})
});

function addRole(memberId, roleName, callback){
	let id = makeid(32);
	let relativeUrl = "/authorization/" + id;
	let role = {};
	role.memberId = memberId;
	role.role = roleName;
	callCouch(relativeUrl, "PUT",role, callback);
}

function getMember(memberId, callback){
	let relativeUrl = "/member/" + memberId;
	callCouch(relativeUrl, "GET", null, callback);
}

function updateMember(member, callback){
	let relativeUrl = "/member/" + member._id;
	callCouch(relativeUrl, "PUT", member, callback);
}

function removePromotionRequest(grantorMemberId, memberId, roleName, response, callback){
	//get the member record
	getMember(memberId, function(error, data){
		if(handleError(error, response, "Failed to remove promotion request.", 400))
			return;
		let requestName = "request_" + roleName.toLowerCase();
		let updateInfo = { "dateGranted": Date.now(), "grantorMemberId": grantorMemberId};
		data[requestName] = updateInfo;//disable request
		updateMember(data, function(error, data){
			if(handleError(error, response, "Failed to disable request.", 400))
				return;
			updateInfo.grantee = memberId;
			updateInfo.roleName = roleName;
			callback(null, updateInfo);
		})
	})
}

app.post('/members/promotions/pending', function(request, response){
	verifyToken(request, response, function(error, response, data){
		let grantorMemberId = data.memberId;
		isInRole(data.memberId, "Philosopher-Ruler", response, function(error, response, data){ //authorization
			if(handleError(error, response, "No matching role found.", 401))
				return;
			isInRole(request.body.targetMemberId, request.body.targetRole, response, function(error, response, data){
				if(!varset(error)){
					response.json(data);//role was previously added already
				}
				addRole(request.body.targetMemberId, request.body.targetRole, function(error, data){
					if(handleError(error, response, "Failed to add role.", 400))
						return;
					removePromotionRequest(grantorMemberId, request.body.targetMemberId, request.body.targetRole, response, function(error, data){
						if(handleError(error, response, "Failed to remove original promotion request.", 301))
							return;
						response.json(data);
					})
				})				
			})
		})
	})	
})

app.get('/users/:facebookUserId/search', function(request, response){
	verifyToken(request, response, function(error, response, data){
		let startkey = "[\"" + request.params.facebookUserId + "\",\"" + request.query.keyword + "\"]"
		let endkey = "[\"" + request.params.facebookUserId + "\",\"" + request.query.keyword + "zzzzzzzzzzzzzzzzzzzzzzz\"]"
		let relativeUrl = "/my_site_biases/_design/search/_view/search_idx?startkey=" + startkey + "&endkey=" + endkey
		callCouch(relativeUrl, "GET", null, function(error, data){
			let parsedRows = data.rows
			let result = parsedRows.reverse().map((couchRow) => {
				let item = couchRow.value;
				item.id = item._id;
				delete item._id;
				delete item._rev;
				return item;
			});
			console.log("search", result)
			response.json(result);
		})
	})
})

app.get('/', function(request, response){
	response.redirect('/documentation/')
})

//better then basic callCouch because we get the article and not
//all of the meta-data
function getArticleFromCouch(articleId, couchCallback){
	var relativeUrl = "/site_biases/" + articleId;
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(varset(error)){
			couchCallback(error, data)
		}else{
			article = {}
			if(data !== undefined){
				article = data
			}
			couchCallback(null, article)
		}
	})//couchCallback expects (error, data)
}

function updateArticleInCouch(article, couchCallback){
	var relativeUrl = "/site_biases/" + article._id;
	callCouch(relativeUrl, "PUT", article, couchCallback)
}

function calculateCritiqueScore(category, critiques, articleLength){
	let matches = critiques.filter((a) => a.errorType == category)
	return (matches.length / articleLength)
}

app.post('/articles/:articleId/critique', function(request, response){
	verifyToken(request, response, function(error, response, data){
		getArticleFromCouch(request.params.articleId, function(error, data){
			if(handleError(error, response, "Specified article was not found.", 400))
				return;
			if(data.critiques == undefined){
				data.critiques = []
			}
			let tcritique = request.body
			let article = data
			article.critiques.push(tcritique)
			let articleLength = article.data.length / 8 //average reader preferred sentence length
			if(tcritique.errorType == "out-of-context")
				article.outOfContextScore = calculateCritiqueScore("out-of-context", article.critiques, articleLength)

			if(tcritique.errorType == "factual-error")
				article.factualErrorScore = calculateCritiqueScore("factual-error", article.critiques, articleLength)

			if(tcritique.errorType == "logical-error")
				article.logicalErrorScore = calculateCritiqueScore("logical-error", article.critiques, articleLength)

			updateArticleInCouch(data,  function(error, data){
				if(handleError(error, response, "Failed to add critique.", 400))
					return;
				article.id = article._id
				delete article._id
				delete article._rev
				response.json(article)
			})
		})
	})	
})

app.use('/documentation', express.static('docs'))

app.listen((process.env.PORT || 3000), function(){
	 console.log("Server is running.");
});