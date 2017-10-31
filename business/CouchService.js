var COUCH_LOG_ENABLED = (process.env.COUCH_LOG_ENABLED || "no");
console.log("CouchDb Call Logging Enabled:", COUCH_LOG_ENABLED);

exports.callCouch = function(relativeUrl, method, data, callback, parms){
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

exports.parseCouchResponse = function(couchData, callback, parms){
	if(!varset(couchData)){
		var err = {};
		err.message = "Variable 'data' was null or undefined in parseCouchResponse.";
		callback(err, null);		
	}else{
		var jsonCouch = couchData;
		if(typeof couchData !== "object"){
			jsonCouch = JSON.parse(couchData);
		}
		if(!varset(jsonCouch.error)){
			callback(null, jsonCouch, parms);
		}else{
			callback(jsonCouch, null);
		}		
	}
}
