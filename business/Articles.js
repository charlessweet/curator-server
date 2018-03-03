//TODO: figure out a better way to do this
var couchdburl = (process.env.COUCHDB_SERVER || "http://localhost:5984")
var biasAlgorithmVersion = (process.env.BIAS_ALGORITHM_VERSION || "V2");

console.log("Bias Algorithm Version (requested):",biasAlgorithmVersion);

var couch = require('./Couch.js')
var phantom = require("../phantom-relay.js")
var common = require('./Common.js')
var url = require("url")
var bias = require("../bias.js")
var err = require('./Error.js')
var queryString = require("querystring")

function addBadLink(link, callback){
	var relativeUrl = "/bad_links/" + new Buffer(link).toString("base64");
	var details = {};
	details.isBad = true;
	details.link = queryString.escape(link);//non base64 version
	details.likelyCause = "Too many redirects.";
	 couch.callCouch(relativeUrl, "PUT", details, function(error, data){
		if(common.varset(error)){
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

function addSiteForUser(requestingUserId, bias, callback){
	//add to general site table
	console.log("addSiteForUser", requestingUserId)
	var id = new Buffer(bias.link).toString("base64") + "_" + requestingUserId;
	bias.userId = requestingUserId;
	var relativeUrl = "/my_site_biases/" + id;
	 couch.callCouch(relativeUrl, "PUT", bias, function(error,data){
		if(common.varset(error)){
			err.addToStackTrace(error, "addSiteForUser");
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
	 couch.callCouch(relativeUrl, "PUT", bias, function(error,data){
		if(common.varset(error)){
			err.addToStackTrace(error, "addSiteToDatabase");
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

function checkKnownBadLinks(link, callback){
	var relativeUrl = "/bad_links/" + new Buffer(link).toString("base64")
	var linkInfo = {}
	linkInfo.link = link
	linkInfo.b64link = new Buffer(link).toString("base64")
	 couch.callCouch(relativeUrl, "GET", null, function(error, data){
		if(common.varset(error)){
			if(error.error === "not_found"){
				callback(null, linkInfo)
			}else{
				callback(error, null)				
			}
		}else{
			if(data.isBad){
				callback(data, null)
			}else{
				callback(null, linkInfo)
			}
		}
	})
}

function getTextUsingRequest(link, callback){
	var request = {"url":link, "method":"GET"}
	requestCall(request, function(err, resp, data){
		if(common.varset(err)){
			callback(err, null)
		}else{
			callback(null, data)
		}
	})	
}

function useAlgorithmVersion(version){
	if(!phantom.isReady){
		console.err("phantom-relay.js reports that phantom is not available or in a usable state.")
	}
	return (biasAlgorithmVersion === version && phantom.isReady)	
}

exports.analyzeLink = function(validationQuery, callback){
	let ret = {isWhiteListed:false, selfLabel:validationQuery.selfLabel, link:validationQuery.linkToValidate, biasScore:0, length:0}
	ret.title = (validationQuery.title === "" ? null : validationQuery.title)
	ret.description = (validationQuery.description === "" ? null : validationQuery.description)
	if(!common.varset(ret.link)){
		//do nothing
		ret.link = "Link was null or undefined."
		callback(ret, null)
	}else{
		checkKnownBadLinks(validationQuery.linkToValidate, function(e3, data){
			if(common.varset(e3)){
				callback(e3, null)
				return
			}else{
				var urlObj = url.parse(validationQuery.linkToValidate)
				if(urlObj === null || urlObj.pathname === null){
					callback({"error":"Url parsed was invalid."}, null)
					return
				}
				
				var id = new Buffer(validationQuery.linkToValidate).toString("base64") + "_" + validationQuery.requestingUserId
				var relativeUrl = "/my_site_biases/" + id
				 couch.callCouch(relativeUrl, "GET", bias, function(error,data){
					if(common.varset(error)){
						if(error.error === "not_found"){
							var getText = getTextUsingRequest
							if(useAlgorithmVersion("V2")){
								getText = phantom.extractText
							}
							getText(ret.link, function(error, pageData){
								if(useAlgorithmVersion("V2") && !common.varset(ret.title)){
									if(pageData !== null){
										var idx = pageData.lastIndexOf("`") + 1
										if(idx > 0 && idx < pageData.length){
											ret.title = common.htmlEscape(pageData.substring(idx))									
										}										
									}else{
										error = {"error":"No data in document."}
									}
								}
								if(!common.varset(ret.title)){
									var startIndex= urlObj.pathname.lastIndexOf("/")
									var title = urlObj.pathname.substring(startIndex)
									if(title.length > 25){
										title = title.substring(0, 25) + "..."
									}
									ret.title = title
								}
								if(!common.varset(error)){
									   bias.checkBias(pageData, function(score, terms){
										   console.log("1 link imported: " + ret.link.substring(0, 255))
										   ret.length = pageData.length
										   ret.biasScore = parseFloat(score)
										   //if bias score is 0 or pageData is 0 bytes then error
										   if(ret.length === 0 || ret.biasScore === 0){
											   addBadLink(ret.link, function(err,data){
												   var error = {"error":"Article was zero length or bias score was zero."}
												   callback(error, null)
											   })
											   return											   
										   }
										   ret.data = pageData
										   ret.algver = 2
										   ret.scaleScore = bias.scaleAlgV2(score)
										   ret.biasTerms = terms
										   ret.url = urlObj
										   ret.created = new Date()
										   ret.description = validationQuery.description
										   addSiteToDatabase(validationQuery.requestingUserId, ret, function(error, data){
										   		//console.log("in addSiteToDatabase", data.length, ret.length)
											   if(common.varset(error)){
												   callback(error, null)  
											   }else{
												   callback(null, ret)		   
											   }
										   })
									   })
								}else{
									addBadLink(ret.link, function(err, data){
										if(common.varset(err)){
											callback(err, null)
										}else{
											callback(data, null)//in both cases, the link was bad
										}
									})
								}
						 	})					
						}else{
							callback(error, null)//database problem
						}
					}else{
						var e2 = {}
						e2.error = "conflict"
						callback(e2, null)
					}
				})				
			}
		})
	}	
}

exports.getArticlesForStream = function(count,offset){
	const getArticlesForStreamPromise = new Promise((resolve,reject) => {
		let relativeUrl = "/site_biases/_design/articletext/_view/article_latest_idx?descending=true&limit=" + count + "&reduce=false&skip=" +  offset
		couch.callCouch(relativeUrl, "GET", null, function(error,data){
			if(common.varset(error)){
				reject(error)
			}else{
				let parsedRows = data.rows
				let result = parsedRows.map((couchRow) => {
					let item = couchRow.value;
					item.id = item._id;
					delete item._id;
					delete item._rev;
					return item;
				});
				resolve(result);
			}
		});
	});
	return getArticlesForStreamPromise;
}


exports.getArticlesForUser = function(userId){
	const getArticlesForUserPromise = new Promise((resolve, reject) => {
		var relativeUrl = "/my_site_biases/_design/my_sites/_view/my_sites_idx?limit=100&reduce=false&startkey=%22" + userId + "%22&endkey=%22" + userId + "%22";
		//retrieve biases for the individual
		couch.callCouch(relativeUrl, "GET", null, function(error, data){
			if(common.varset(error)){
				reject("Failed while searching for articles for user.")
			}else{
				var parsedRows = (common.varset(data.rows) ? data.rows.map((r)=>{return r.value}) : [])
				resolve(parsedRows)
			}
		})
	})
	return getArticlesForUserPromise
}

exports.changeOwner = function(articleList, callingUserId, newOwnerUserId){
	const changeOwnerPromise = new Promise((resolve, reject) => {
		for(let i = 0; i < articleList.length; i++){
			articleList[i].userId = newOwnerUserId
			articleList[i].lastModifiedBy = callingUserId
			articleList[i].lastModifiedDate = new Date()
		}
		let relativeUrl = "/my_site_biases/_bulk_docs"
		let docs= {}
		docs.docs = articleList
		couch.callCouch(relativeUrl, "POST", docs, function(error, data){
			if(common.varset(error))
				reject("Some articles could not be changed")
			else
				resolve(data)
		})
	})
	return changeOwnerPromise
}
