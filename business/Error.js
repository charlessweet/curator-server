exports.handleError = function(error, response, failureMessage, failureHttpCode){
	if(varset(error)){
		reportError(error, failureMessage, response, failureHttpCode);
		return true;
	}
	return false;
}

exports.reportError = function(error, message, response, statusCode){
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

exports.addToStackTrace = function(error, callerName){
	if(!varset(error.stack)){
		error.stack = [];
	}
	error.stack.push(callerName);
}
