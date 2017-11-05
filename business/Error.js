var common = require('./Common.js')

exports.handleError = function(error, response, failureMessage, failureHttpCode){
	if(common.varset(error)){
		exports.reportError(error, failureMessage, response, failureHttpCode);
		return true;
	}
	return false;
}

exports.reportError = function(error, message, response, statusCode){
	if(!common.varset(statusCode)){
		statusCode = 400;
	}
	if(response !== undefined){
		try{
			response.status(statusCode)
			response.json({"message":message,"error":error});	
			response.end()	
		}catch(e){
			let stack = {}
			exports.addToStackTrace(stack)
			console.log(e, stack, response, statusCode, message)
		}
	}
}

exports.addToStackTrace = function(error, callerName){
	if(!common.varset(error.stack)){
		error.stack = [];
	}
	error.stack.push(callerName);
}
