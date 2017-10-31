/*
These are all async and rely on the callback pattern (jsonMessage, error, data) => {}
*/
 exports.verifyUserExists = function(userId, response, callback){
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

 exports.getMember = function(memberId, callback){
	let relativeUrl = "/member/" + memberId;
	callCouch(relativeUrl, "GET", null, callback);
}

 exports.getMemberByUsernamePassword = function(userName, password, response, callback){
	let relativeUrl = "/member/_design/memberships/_view/members_by_username?limit=2&reduce=false&startkey=%22" + userName + "%22&endkey=%22" + userName + "%22"
	callCouch(relativeUrl, "GET", null, function(error, data){
		
	})
}

 exports.determineRolesForUser = function(memberId, response, callback){
	let relativeUrl = "/authorization/_design/roles/_view/rolelist_idx?limit=10&reduce=false&startkey=%22" + memberId + "%22&endkey=%22" + memberId + "%22";
	callCouch(relativeUrl, "GET", null, function(error, data){
		if(handleError(error, response, "Could not add roles for user.", 400))
			return;
		let roles = data.rows.map((x) => x.value);
		callback(null, response, roles)
	})
}
