var COUCH_LOG_ENABLED = (process.env.COUCH_LOG_ENABLED || "no")
var couchdburl = (process.env.COUCHDB_SERVER || "http://localhost:5984")
var apiKey = (process.env.COUCHDB_APIKEY || "service_user")
var apiPassword = (process.env.COUCHDB_APIPASSWORD || "nzskBUVuvY1YAbRmMBnP")
var couchauthheader = "Basic " + new Buffer(apiKey + ":" + apiPassword).toString("base64")

console.log("CouchDb Call Logging Enabled:", COUCH_LOG_ENABLED)
console.log("CouchDB URL:", couchdburl)

var common = require('./Common.js')
var requestCall = require("request")

exports.callCouch = function(relativeUrl, method, data, callback, parms){
	//console.log(relativeUrl)
	if(COUCH_LOG_ENABLED === "yes"){
		console.error(method, relativeUrl)		
	}
	var url = couchdburl + relativeUrl
	var request = {"url":url, "headers":{"Authorization":couchauthheader}, "method":method}
	if(common.varset(data)){
		request.json = data
	}
	requestCall(request, function(error, nestedResponse, dataReturned){
		parseCouchResponse(dataReturned, callback, parms)
	})
}

parseCouchResponse = function(couchData, callback, parms){
	if(!common.varset(couchData)){
		var err = {}
		err.message = "Variable 'data' was null or undefined in parseCouchResponse."
		callback(err, null)		
	}else{
		var jsonCouch = couchData
		if(typeof couchData !== "object"){
			jsonCouch = JSON.parse(couchData)
		}
		if(!common.varset(jsonCouch.error)){
			callback(null, jsonCouch, parms)
		}else{
			callback(jsonCouch, null)
		}		
	}
}
