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
var auth = require('./business/Authentication.js');
var err = require('./business/Error.js');
var couch = require('./business/Couch.js');
var common = require('./business/Common.js');
var articles = require('./business/Articles.js');
var bias = require("./bias.js")

var bodyParser = require('body-parser');
var path = require("path");
var express = require("express");
var app = express();
var sha256 = require('js-sha256');

var fbapp_id = (process.env.FB_APP_ID || "382449245425765");
var fbapp_secret = (process.env.FB_APP_SECRET || "50d4cbbc4f431f21f806d50dbe0ed614");

var AUTOMONITOR_LOG_ENABLED = (process.env.AUTOMONITOR_LOG_ENABLED || "yes");
var FB_POLLING_RATE = (process.env.FB_POLLING_RATE || 1000*60*5);
var email = require('./business/Email.js');

//print config info
function printConfig(){
	console.log("Facebook AppId:", fbapp_id);
	console.log("PhatomJS Available:", (phantom.isReady() ? "yes" : "no"));
	console.log("Facebook Polling Rate:", FB_POLLING_RATE + " ms");
	console.log("Automonitor Log Enabled:", AUTOMONITOR_LOG_ENABLED);
}

printConfig();

//used to persist user within a single call
var users = []; //might want to replace with distributed key-value system eventually

app.use(auth.allowCrossDomain);
app.use(auth.validateBiasCheckerApp);
app.use(auth.validateJWT);

app.use(bodyParser.json());//json support
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies	

var salt = common.makeid();//once per application load

var allowedAccounts = 100;
function verifyAccountsAreAvailable(response, callback){
	var relativeUrl = "/facebook_users/_design/unique_users/_view/unique_users_idx?limit=100&reduce=true&group=true";
	 couch.callCouch(relativeUrl, "GET", null, function(error,data){
		if(common.varset(error)){
			err.reportError(error, "Failed to retrieve estimated available accounts.", response, 401);					
		}else{
			var parsedRows = (common.varset(data.rows) ? data.rows : []);
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

function getSettingsForUser(userId, callback){
	var relativeUrl = "/user_settings/" + userId;
	 couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(common.varset(error)){
			callback(error, null);
		}else{
			callback(null, data);
		}
	});
}

function updateUserSettings(settings, callback){
	var id = settings.userId;
	var relativeUrl = "/user_settings/" + id;
	 couch.callCouch(relativeUrl, "PUT", settings, function(error, data){
		if(common.varset(error)){
			if(error.reason === "Document update conflict."){
				 couch.callCouch(relativeUrl, "GET", null, function(error2,data2){
					if(common.varset(error2)){
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
	 couch.callCouch(relativeUrl, "PUT", bias, function(error, data){
		if(common.varset(error)){
			if(error.reason === "Document update conflict."){
				 couch.callCouch(relativeUrl, "GET", null, function(error,data){
					if(common.varset(error)){
						err.reportError(error, "Failed to retrieve site bias for update.", response);
					}else{
						var bias2 = data;
						bias2.myScore = bias.myScore;
						updateSiteForUser(requestingUserId, bias2, response);						
					}
				});
			}else{
				err.reportError(error, "Failed to save site estimate.", response);
			}
		}else{
			response.json(bias);
		}
	});	
}

function verifyValidation(error, data){
	if(common.varset(error)){
		if(error.error !== "conflict" && !common.varset(error.isBad)){
			err.reportError(error, "Link validation failed for the reason indicated.");
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
		if(common.varset(err)){
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
		if(common.varset(error)){
			err.reportError(error, "Validate feed failed.");
		}else{
			var list = JSON.parse(data);
			if(!common.varset(list.error)){
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
						articles.analyzeLink(query, verifyValidation);
					}
				}			
			}else{
				err.reportError(list.error, "Failed to retrieve feed from Facebook.");
			}			
		}
	});
}

function validateForUnexpiredUsers(error, data, tokenData){
	if(common.varset(error)){
		err.reportError(error, "Failed to retrieve unexpired user.");					
	}else{
		if(data.rows.length > 0){
			var fbAccessToken = data.rows[0].value.accessToken;
			var ogToken = tokenData.settings.originalAccessToken;
			if(fbAccessToken !== ogToken){
				var settings = tokenData.settings;
				settings.originalAccessToken = fbAccessToken;
				extendToken(fbAccessToken, function(error, data){
					if(common.varset(error)){
						err.reportError(error, "Failed to extend the access token.");					
					}else{
						if(AUTOMONITOR_LOG_ENABLED === "yes"){
							console.log("Extended access token successfully.");
						}
						settings.longTermAccessToken = data.access_token;
						validateFeed(data.access_token, tokenData.userId);
						updateUserSettings(settings, function(error, data){
							if(common.varset(error)){
								err.reportError(error, "Failed to validate unexpired users.");
							}else{
								console.log("UPDATED TOKEN");
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
	 couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(common.varset(error)){
			err.reportError(error, "Failed to find automonitor settings.");
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
					if(common.varset(tokenData.settings)){
						relativeUrl = "/facebook_users/_design/unexpired_users/_view/unexpired_users_idx?limit=100&reduce=false&startkey=%22" + facebookHashedUserId + "%22&endkey=%22" + facebookHashedUserId + "%22";
						 couch.callCouch(relativeUrl, "GET", null, validateForUnexpiredUsers, tokenData);						
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
	 auth.verifyToken(request,  response, function(error, response, data){
		if(!authorized(request.query.userID, request.query.biasToken)){
			response.status(403);
			response.json({"error":"unauthorized"});			
		}else{
			var relativeUrl ="/my_site_biases/_design/reasoning/_view/reasoning_idx?limit=100&reduce=false&startkey=%22" + request.query.link + "%22&endkey=%22" + request.query.link + "%22";
			 couch.callCouch(relativeUrl, "GET", null, function(error,data){
				var parsedRows = (common.varset(data.rows) ? data.rows : []);
				if(common.varset(error)){
					err.reportError(error, "Failed to retrieve estimated scores.", response);					
				}else{
					response.json(parsedRows);
				}
			});
		}
	});
});

app.post('/analyze', function(request, response){
	let linkReq = request.body
	linkReq.requestingUserId = request.jwt.userId
	articles.analyzeLink(request.body, (error, data)=> {
		if(common.varset(error)){
			if(error.error === "conflict"){
				err.reportError({"error":"Request already exists."}, "No reason to revalidate since the request already exists.", response, "409")
			}else{
				err.reportError(error, "Failed to validate.", response, 400)					
			}
		}else{
			response.json(data)
		}
	});
});

app.post('/password-reset/:passwordResetRequestId', function(request, response){
	//get member using password request id
	auth.resetPasswordByRequest(request.params.passwordResetRequestId, request.body.password, function(error, member){
		if(common.varset(error)){
			err.reportError(error, "Failed to reset.", response, 400)
		}else{
			response.json({"status":"password changed"})
		}
	})
})

app.post('/my/password', function(request, response){
	auth.getMember(request.jwt.memberId, function(error, member){
		let relativePwdUrl = "/password/" + request.jwt.memberId
		couch.callCouch(relativePwdUrl, "GET", null, function(error, password){
			if(common.varset(error)){
				err.reportError(error, "Failed to validate.", response, 400)
			}else{
				password.value = auth.generatePasswordHash(request.body.password, member.password_salt)
				couch.callCouch(relativePwdUrl, "PUT", password, function(error, data){
					if(common.varset(error)){
						err.reportError(error,"Failed to set password for user.", response)
					}else{
						response.json({"status":"password changed"})
					}
				})		
			}
		})		
	})
})

//get articles for a user
//role:user
app.get('/my/articles', function(request, response){
	var relativeUrl = "/my_site_biases/_design/my_sites/_view/my_sites_idx?limit=100&reduce=false&startkey=%22" + request.jwt.userId + "%22&endkey=%22" + request.jwt.userId + "%22";
	//retrieve biases for the individual
	articles.getArticlesForUser(request.jwt.userId)
	.then((parsedRows)=>{
		var i = 0;
		for(i = 0; i < parsedRows.length; i++){
			if(parsedRows[i].title === undefined){
				parsedRows[i].title = parsedRows[i].link;
			}
			if(common.varset(parsedRows[i].algver) && parsedRows[i].algver === 2){
				parsedRows[i].scaleScore = bias.scaleAlgV2(parsedRows[i].biasScore);
			}else{
				parsedRows[i].scaleScore = bias.scale(parsedRows[i].biasScore);
			}
			parsedRows[i].biasScore = parseFloat(parsedRows[i].biasScore);								
		}
		var result = parsedRows.map((article) => {
			let item = article;
			item.id = item._id;
			delete item._id;
			delete item._rev;
			return item;
		});
		response.json(result);
	})
	.catch((error)=>{
		err.reportError(error, "Failed to retrieve my site scores.", response)			
	})
});

//analylize a link for bias and add to all bias articles
//role:user
app.put('/users/:userId/articles', function(request, response){
	auth.verifyToken(request, response, function(error, response, data){
		var validatedPost = request.body;
		if(common.varset(validatedPost) && common.varset(validatedPost.userId) && !isNaN(validatedPost.myScore)){
			try
			{
				validatedPost.myScore = parseInt(validatedPost.myScore);
				updateSiteForUser(validatedPost.userId, validatedPost, response);		
			}catch(ex){
				err.reportError(ex, "Invalid score for user.", response);
			}
		}else{
			err.reportError(validatedPost, "Invalid data supplied for validation.", response);
		}
	});
});

//retrieve settings for a user
//role:user
app.get('/users/:userId/settings', function(request, response){
	 auth.verifyToken(request, response, function(error, response, data){
		getSettingsForUser(request.query.userId, function(error, data){
			if(common.varset(error)){
				err.reportError(error, data, response);
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
	 auth.verifyToken(request, response, function(error, response, data){
		updateUserSettings(request.body, function(error, data){
			if(common.varset(error)){
				err.reportError(error, "Failed to save user settings.", response);
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
		err.reportError(request.query, "Failed to retrieve bookmark - no id.", response);		
	}else{
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				err.reportError(error, "Failed to retrieve bookmark.", response);				
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
	 auth.verifyToken(request, response, function(error, response, data){
		var bookmarkInfo = {};
		bookmarkInfo= request.body;
		if(bookmarkInfo._id !== undefined){
			delete bookmarkInfo._id;
			delete bookmarkInfo._rev;
			delete bookmarkInfo.isWhiteListed;
			delete bookmarkInfo.url;			
		}
		var relativeUrl = "/bookmarks/" + common.makeid(12);
		 couch.callCouch(relativeUrl, "PUT", bookmarkInfo, function(error, data){
			if(common.varset(error)){
				err.reportError(error, "Failed to create bookmark.", response);				
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
	 auth.verifyToken(request, response, function(error, response, data){
		articles.analyzeLink(request.body, function(error, data){
			if(common.varset(error)){
				if(error.error === "conflict"){
					err.reportError({"error":"Request already exists."}, "No  reason to revalidate since the request already exists.", response, 409);
				}else{
					err.reportError(error, "Failed to validate.", response, 400);					
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
		var relativeUrl = "/site_biases/" + request.params.articleId;
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				err.reportError(error, "Failed to retrieve article.", response);			
			}else{
				if(data.tags !== undefined){
					var tag = ";" + request.params.tag + ";";
					data.tags = data.tags.replace(tag, "");
					 couch.callCouch(relativeUrl, "PUT", data, function(error, data){
						if(common.varset(error)){
							err.reportError(error, "Failed to add tag.", response);
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

//get member-level article bias information
//role: owner
//TODO: finish this endpoint - should filter by userid
app.get('/users/:userId/articles/:myArticleId', function(request,response){
	var relativeUrl = "/my_site_biases/" + request.params.myArticleId;
	 couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(common.varset(error)){
			err.reportError(error, "Failed to retrieve article.", response);			
		}else{
			var id = new Buffer(data.link).toString("base64");
			var parentUrl = "/site_biases/" + id;
			 couch.callCouch(parentUrl, "GET", null, function(error,data){
				if(common.varset(error)){
					err.reportError(error, "Failed to retrieve article 2.", response);					
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
	 auth.verifyToken(request, response, function(error, response, data){
		var relativeUrl = "/site_biases/" + request.params.articleId;
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				err.reportError(error, "Failed to retrieve article.", response);				
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
		var relativeUrl = "/site_biases/" + request.params.articleId;
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				err.reportError(error, "Failed to retrieve article.", response);			
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
					 couch.callCouch(relativeUrl, "PUT", data, function(error, data){
						if(common.varset(error)){
							err.reportError(error, "Failed to add tag.", response);
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

//retrieve the list of keywords associated with an article
//role:user
app.get('/articles/:articleId/keywords', function(request, response){
		var relativeUrl = "/site_biases/" + request.params.articleId;
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				err.reportError(error, "Failed to retrieve article.", response);				
			}else{
				var ret = {};
				ret.keywords = data.keywords;
				response.json(ret);
			}
		});		
});

//set the list of keywords associated with an article
//role: philosopher-ruler
app.put('/articles/:articleId/keywords', function(request, response){
		var keywords = request.body;
		var relativeUrl = "/site_biases/" + request.params.articleId;
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				err.reportError(error, "Failed to retrieve article.", response);			
			}else{
				var res = {};
				res.keywords = keywords;
				res.articleId = request.params.articleId;
				data.keywords = keywords;
				 couch.callCouch(relativeUrl, "PUT", data, function(error, data){
					if(common.varset(error)){
						err.reportError(error, "Failed to add tag.", response);
						return;
					}else{
						res.status = "saved";
						response.json(res);
					}
				});					
			}
		});
});

//role:user
app.get('/articles/:articleId/text', function(request,response){
	var id = request.params.articleId;
	var relativeUrl = "/site_biases/_design/articletext/_view/articletext_idx?limit=1&reduce=false&startkey=%22" + id + "%22&endkey=%22" + id + "%22";
	//console.log(relativeUrl);
	 couch.callCouch(relativeUrl, "GET", null, function(error,data){
		if(common.varset(error)){
			err.reportError(error, "Failed to retrieve summaries.",response);
		}else{
			response.json(data);
		}
	});
});

app.get('/articles/:articleId', function(request, response){
	var id = request.params.articleId

	var relativeUrl = "/site_biases/" + id
//	console.log(relativeUrl);
	 couch.callCouch(relativeUrl, "GET", null, function(error,data){
		if(common.varset(error)){
			err.reportError(error, "Failed to retrieve summaries.",response);
		}else{
			delete data._rev
			data.id = data._id
			delete data._id
			response.json(data);
		}
	})	

})

//retrieve article summaries for all articles in the database.  if missing_tag is definied, then articles must *not* have the 
//missing tag in their keywords to show up in the returned result set
//role:user
app.get('/summaries', function(request,response){
		var limit = request.query.limit;
		var tag = request.query.missing_tag;
		var relativeUrl = "/site_biases/_design/articletext/_view/articleid_idx?limit=" + limit + "&reduce=false";
		if(tag !== undefined){
			relativeUrl= "/site_biases/_design/" + tag + "_queue/_view/" + tag + "_queue_idx?limit=" + limit + "&reduce=false";
		}
		//console.log(relativeUrl);
		 couch.callCouch(relativeUrl, "GET", null, function(error,data){
			if(common.varset(error)){
				err.reportError(error, "Failed to retrieve article summaries.",response);
			}else{
				response.json(data);
			}
		});
});

app.get('/articles', function(request,response){
	var limit = parseInt(request.query.limit === undefined ? 40 : request.query.limit, 10)
	var offset = parseInt(request.query.offset === undefined ? 0 : request.query.offset, 10)
	articles.getArticlesForStream(limit,offset)
		.then((results) => {
			response.json(results);
		})
		.catch((error)=>{
			err.reportError(error, "Failed to load stream.", response);
		});
});

app.post('/verify', function(request, response){
	
	
})

const EmailTemplates = ["Welcome", "PasswordReset"]
app.post('/password-reset', function(request, response){
	//capture necessary information
	auth.checkIfMemberExists(request.body.email, function(error, data){
		if(common.varset(error) || data.memberId === undefined){
			err.reportError(error, "Could not determine user status.", response);
		}else{
			auth.savePasswordResetRequest(request.body.email, data.memberId, common.makeid(64) /* pwdreset id*/, function(error, savedReset){
				if(common.varset(error)){
					err.reportError(error, "Failed to save password reset request.",response);
				}else{
					//send corresponding reset email
//					console.log("saved", savedReset)
					let parms = {}
					parms.rootUrl = request.headers.origin
					parms.resetRequestId = savedReset.passwordRequestId
					parms.toEmail = request.body.email
					parms.subject = "Curator: Password Reset Request Accepted"
					email.sendEmailFromTemplate(EmailTemplates[1], parms);	

					let ret = {}
					ret.passwordReset = true
					//only want id for return
					response.json(ret)
				}
			})
		}
	})
})

app.post('/register', function(request, response){
	//create member object
	let member = {};
	member.email = request.body.email;
	member.userId = common.makeid(64);
	member.password_salt = common.makeid(64);
	member.emailConfirmed = false
	let id = common.makeid(64)

	//create password object
	var password = {};
	password.value = auth.generatePasswordHash(request.body.password, member.password_salt);

	auth.checkIfMemberExists(member.email, function(error, data){
		if(common.varset(error)){
			err.reportError("Failed to register user.", "Could not determine user status.", response);
		}else{
			if(data.exists){
				err.reportError("Failed to register user.", "User already exists.", response, 409);
			}else{
				couch.callCouch("/password/" + id, "PUT", password, function(error, data){
					if(common.varset(error)){
						err.reportError(error,"Failed to set password for user.", response);
					}else{
						 couch.callCouch("/member/" + id, "PUT", member, function(error,data){
							if(common.varset(error)){
								err.reportError(error, "Failed to create login for member.", response)
							}else{
								var ret = {}
								ret.memberId = id
								/*
								  Send email. This isn't wholly required to have an active account
								  so fire-and-forget.
								*/
								let parms = {}
								parms.rootUrl = request.headers.origin
								parms.toEmail = member.email
								parms.subject = "Welcome to Curator!"
								email.sendEmailFromTemplate(EmailTemplates[0], parms);

								response.json(ret)
							}
						})
					}
				})				
			}
		}
	})
})

//register a user with an existing facebook login to a BiasChecker login
//role: user (must be the same user)
app.post('/members/:memberId/register', function(request, response){
	 auth.verifyToken(request, response, function(error, response, data){
		if(!authorized(request.params.userId, request.query.biasToken)){
			err.reportError("Failed to register user.", "Target and token don't match.", response, 401);			
		}else if(request.body.password === undefined || request.params.userId === undefined || 
			request.body.email === undefined){
			err.reportError("Failed to register user.", "No password or user id was supplied.", response);
		}else{
			auth.verifyUserExists(request.params.userId, response, function(error, response, data){
				if(common.varset(error)){
					err.reportError(error, "Failed to register user.", response);
				}else{
					//create member object
					var member = {};
					member.userId = request.params.userId;
					member.email = request.body.email;
					member.request_guardian = request.body.guardian;
					var id = common.makeid(64);

					//create password object
					var password = {};
					password.value = auth.generatePasswordHash(request.body.password, request.body.userId);

					 couch.callCouch("/password/" + id, "PUT", password, function(error, data){
						if(common.varset(error)){
							err.reportError(error,"Failed to set password for user.", response);
						}else{
							 couch.callCouch("/member/" + id, "PUT", member, function(error,data){
								if(common.varset(error)){
									err.reportError(error, "Failed to create login for member.", response);
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
	 couch.callCouch(relativeUrl, "PUT", authInfo, function(error, data){
		if( err.handleError(error, response, "Failed to save facebook user.", 400))
			return;
		confirmFacebookUser(authInfo, response, callback);
	})
}

//create a new user account
app.post('/members', function(request, response){
	let member = {};
	member.member_id = common.makeid(64);
	member.email = request.body.email;
	member.password_salt = common.makeid(64);
	member.roles = [];
	let password = auth.generatePasswordHash(request.body.password, member.password_salt);
	 couch.callCouch("/password/" + member.memberId, "PUT", password, function(error, data){
		if(common.varset(error)){
			err.reportError(error,"Failed to set password for member.", response);
		}else{
			 couch.callCouch("/member/" + member.memberId, "PUT", member, function(error,data){
				if(common.varset(error)){
					err.reportError(error, "Failed to create login for member.", response);
				}else{
					let ret = {"status":"created", "memberId":member.memberId};
					//send notification email
					//user validation flow
					response.json(ret);
				}
			});
		}
	});	
});

app.post('/authenticate/basic', function(request, response){
	let authHeader = request.header("Authorization").split(" ")
	if(authHeader[0] === "Basic"){
		let credentials = new Buffer(authHeader[1], "base64").toString("ascii").split(":")
//		console.log(credentials)
		//console.log(credentials)
		let userName = credentials[0]
		let password = credentials[1]
		//find user and get salt
		auth.getMemberByUsernamePassword(userName, password, response, function(error, member){
			if(common.varset(error)){
				err.reportError({"status":"Authorization credentials invalid."}, "Authorization Failed", response, 401);
			}else{
				auth.determineRolesForUser(member._id, response, function(error, rolesList){
					member.roles = [];
					if(!common.varset(error)){
						member.roles = rolesList
					}
					let payload = {}
					payload.scope = rolesList
					payload.name = member.email
					payload.memberId = member._id
					payload.userId = member.userId
					let jwt = auth.generateJwt(payload);
					//console.log(jwt)
					response.json(jwt);			
				})
			}
		})
	}		
})

//exchange a facebook token for a biasToken - checks w/facebook to determine if token is valid
//role:user
app.post('/authenticate/facebook', function(request, response){
	var fbAuthToken = request.body;

	fbAuthToken.userId = sha256(fbAuthToken.userID);
	fbAuthToken.biasAccessToken = sha256(fbAuthToken.userId + salt);

	delete fbAuthToken.signedRequest;
	delete fbAuthToken.userID;
	delete fbAuthToken.expiresIn;
	delete fbAuthToken.minutes;

	auth.verifyUserExists(fbAuthToken.userId, response, function(error, response, data){
		fbAuthToken.memberId = data.memberId;
		if(common.varset(error)){
			verifyAccountsAreAvailable(response, function(error, response, data){
				if( err.handleError(error, response, "Login failed.  No accounts are available.", 401))
					return;
			});			
		}
		persistUser(fbAuthToken, response, function(error, res, data){
			if(common.varset(error)){
				console.log("User was persisted but failed Facebook ping.");
			}
			determineRolesForUser(fbAuthToken.memberId, response, function(error, res, rolesList){
				if(!common.varset(error)){
					fbAuthToken.roles = rolesList
				}

				let payload = {}
				payload.scope = rolesList
				payload.name = fbAuthToken.name
				payload.memberId = fbAuthToken.memberId
				payload.userId = fbAuthToken.userId
				let jwt = auth.generateJwt(payload);
				response.json(jwt);				
			})
		})
	});
});

function isInRole(memberId, roleName, response, callback){
	let memberRole = memberId + "_" + roleName;
	var relativeUrl = "/authorization/_design/roles/_view/rolesearch_idx?limit=1&reduce=false&startkey=%22" + memberRole.toLowerCase() + "%22&endkey=%22" + memberRole + "%22";
	 couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(common.varset(error)){ //intentional fail if user is not in role
			err.reportError(error, "Failed to determine user role.", response, 401);
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

function updateMember(member, callback){
	let relativeUrl = "/member/" + member._id;
	 couch.callCouch(relativeUrl, "PUT", member, callback);
}

app.get('/users/:facebookUserId/search', function(request, response){
	 auth.verifyToken(request, response, function(error, response, data){
		let startkey = "[\"" + request.params.facebookUserId + "\",\"" + request.query.keyword + "\"]"
		let endkey = "[\"" + request.params.facebookUserId + "\",\"" + request.query.keyword + "zzzzzzzzzzzzzzzzzzzzzzz\"]"
		let relativeUrl = "/my_site_biases/_design/search/_view/search_idx?startkey=" + startkey + "&endkey=" + endkey
		 couch.callCouch(relativeUrl, "GET", null, function(error, data){
			let parsedRows = data.rows
			let result = parsedRows.reverse().map((couchRow) => {
				let item = couchRow.value;
				item.id = item._id;
				delete item._id;
				delete item._rev;
				return item;
			});
//			console.log("search", result)
			response.json(result);
		})
	})
})

app.get('/', function(request, response){
	response.redirect('/documentation/')
})

//better then basic  couch.callCouch because we get the article and not
//all of the meta-data
function getArticleFromCouch(articleId, couchCallback){
	var relativeUrl = "/site_biases/" + articleId;
	 couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(common.varset(error)){
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
	 couch.callCouch(relativeUrl, "PUT", article, couchCallback)
}

function calculateCritiqueScore(category, critiques, articleLength){
	let matches = critiques.filter((a) => a.errorType == category)
	return (matches.length / articleLength)
}

app.post('/articles/:articleId/critique', function(request, response){
	if(request.jwt.scope === undefined ||
		request.jwt.scope.indexOf("guardian") == -1){
		response.status(403)
		return
	}	
	getArticleFromCouch(request.params.articleId, function(error, data){
		if( err.handleError(error, response, "Specified article was not found.", 400))
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
			if( err.handleError(error, response, "Failed to add critique.", 400))
				return;
			article.id = article._id
			delete article._id
			delete article._rev
			response.json(article)
		})
	})
})

app.post('/my/roles', function(request, response){
	//the only roles allowed are from our list
	let rolesAllowed = ["guardian"]
	let roleRequest = request.body
	let jwtDecoded = request.jwt

	auth.requestRole(jwtDecoded.name, jwtDecoded.memberId, jwtDecoded.memberId, roleRequest.roleName, function(error, data){
		if(err.handleError(error, response, "Failed to request role", 400))
			return;

		let domainResponse= {}
		domainResponse.id = data.id
		response.json(domainResponse)
	})
})

app.get('/roles/requests', function(request, response){
	if(request.jwt.scope === undefined ||
		request.jwt.scope.indexOf("philosopher-ruler") == -1){
		response.status(403)
		return
	}
	//the only roles allowed are from our list
	let jwtDecoded = request.jwt

	auth.getRoleRequests(function(error, data){
		if(err.handleError(error, response, "Failed to retrieve role requests", 400))
			return;
		if(common.varset(error)){
			err.reportError(error, "Failed to retrieve estimated scores.", response);					
		}else{
			var parsedRows = (common.varset(data.rows) ? data.rows : [])
			let retRows = parsedRows.map((r) => { 
				var ret = {}
				ret.memberId = r.value.memberId
				ret.requestDate = r.value.requestDate
				ret.requestor = r.value.requestor
				ret.roleName = r.value.roleName
				ret.email = r.value.email
				return ret
			})
			response.json(retRows);
		}
	})
})

app.post('/members/:memberId/roles', function(request, response){
	if(request.jwt.scope === undefined ||
		request.jwt.scope.indexOf("philosopher-ruler") == -1){
		response.status(403)
		return
	}
	//the only roles allowed are from our list
	let jwtDecoded = request.jwt
	let targetMemberId = request.params.memberId
	let roleName = request.body.roleName

	auth.addRole(jwtDecoded.memberId, targetMemberId, roleName, function(error, roleRequest){
		if(err.handleError(error, response, "Failed to grant role requests", 400))
			return;
		if(common.varset(error)){
			err.reportError(error, "Failed to grant the members role.", response);					
		}else{
			var ret = {}
			ret.memberId = targetMemberId
			ret.roleName = roleName
			ret.status = "APPROVED"
			response.json(ret);
		}
	})
})

app.delete('/roles/:roleName/requests/:memberId', function(request, response){
	if(request.jwt.scope === undefined ||
		request.jwt.scope.indexOf("philosopher-ruler") == -1){
		response.status(403)
		return
	}
	//the only roles allowed are from our list
	let jwtDecoded = request.jwt
	let targetMemberId = request.params.memberId
	let roleName = request.params.roleName

	auth.denyRoleRequest(jwtDecoded.memberId, targetMemberId, roleName, function(error, roleRequest){
		if(err.handleError(error, response, "Failed to deny role requests", 400))
			return;
		if(common.varset(error)){
			err.reportError(error, "Failed to deny the members role request.", response);					
		}else{
			var ret = {}
			ret.memberId = targetMemberId
			ret.roleName = roleName
			ret.status = "DENIED"
			response.json(ret);
		}
	})
})

app.post('/my/facebook', function(request, response){
	let jwtDecoded = request.jwt
	let facebookUserId = request.body.facebookUserId
	let totalRecs = 0
	let articlesForUser = articles.getArticlesForUser(facebookUserId)
	.then((articleList) =>{
		articles.changeOwner(articleList, jwtDecoded.userId, jwtDecoded.userId)
		.then((data) => {
			if(articleList.length > 0){
				totalRecs += articleList.length
				articlesForUser.bind(facebookUserId)
			}else{
				response.json({"success":"Migrated " + totalRecs + " records"})
			}
		})
		.catch((error) => {
			console.log(error)
			err.reportError(error, "Failed to upgrade user account", response)
		})
	})
	.catch((error) => {
		err.handleError(error, response, "Failed to deny role requests", 400)
	})
})

app.use('/documentation', express.static('docs'))

app.listen((process.env.PORT || 3000), function(){
	 console.log("Server is running.");
});
