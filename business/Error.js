exports.handleError = function(error, response, failureMessage, failureHttpCode){
	if(varset(error)){
		reportError(error, failureMessage, response, failureHttpCode);
		return true;
	}
	return false;
}
