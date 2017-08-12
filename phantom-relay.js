var path = require('path');
var childProcess = require('child_process');
var phantomjs = require('phantomjs-prebuilt');
var binPath = phantomjs.path;

console.log("using PhantomJS from: " + binPath);

function getText(link, callback){
	var quotedLink = link;
	//var quotedLink = "https://www.google.com";
	var jsPath = path.join(__dirname, 'readwebsite.js');
	var childArgs = [
	                 jsPath
	               ];
	//this calls the phantom script to read the file
	//fine contents are written to stdout
	var readLink = childProcess.spawn(binPath, childArgs);
	if(readLink.stdin !== undefined){
		readLink.stdin.write(link);
		readLink.stdin.end();		
	}else{
		var nolink = {};
		nolink.error = "Child process failed to spawn successfully.";
		nolink.stack = "phantom-relay::getText";
		callback(nolink, null);//can't use it if we don't have it
		return;
	}
	
	var result = [];
	var hasError = false;
	var error = [];
	readLink.stdout.on('data', function(buffer){
			var data = buffer.toString();
			result.push(data);
	});
	
	readLink.stderr.on('data', function(buffer){
		var error = buffer.toString();
		callback(error, null);
		hasError = true;
	});
	
	readLink.on('exit', function(){
		if(!hasError){
			callback(null, result.join(""));			
		}
	});
}

exports.isReady = function(){
	return (phantomjs !== undefined && phantomjs !== null && phantomjs.path !== undefined && phantomjs.path !== null);
};

exports.extractText = function(link, callback){
	getText(link, callback);
};