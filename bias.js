var fs = require("fs");
var async = require("async");
var fileFolder = "./bias/";
var files = [];
var loaded = [];

function performSearch(lexicon, corpus, biasDetails){
	for(var i = 0; i < lexicon.length; i++){
		var pos = 0;
		var term = lexicon[i].trim();
		while((pos = corpus.indexOf(term, pos)) > -1){
			biasDetails.termCount+=term.length;
			biasDetails.terms.push(term);
			pos += lexicon[i].length;
		}
	}	
}

function biasCheckAbstracted(biasFileName, corpus, biasDetails, callback){
	if(loaded[biasFileName] === null || loaded[biasFileName] === undefined){
		var start = process.hrtime();
		var fileName = fileFolder + biasFileName;
//		console.log(fileName);
		fs.readFile(fileName, "utf8", function(err, data){
			var lexicon = data.split("\n");
//			console.log(lexicon[0]);
			if(loaded[biasFileName] === null || loaded[biasFileName] === undefined){
				loaded[biasFileName] = lexicon;
			}
			performSearch(lexicon, corpus, biasDetails);
			var stop = process.hrtime(start);
			//console.info(process.hrtime() + ",IL," + biasFileName.substring(0,2) + ",%d", stop[1]/1000000);
			callback(null, corpus, biasDetails);
		});		
	}else{
		var start2 = process.hrtime();
		var lexicon = loaded[biasFileName];
		performSearch(lexicon, corpus, biasDetails);
		var stop = process.hrtime(start2);
		//console.info(process.hrtime() + ",PL," + biasFileName.substring(0,2) + ",%d", stop[1]/1000000);
		callback(null, corpus, biasDetails);		
	}
}

function hedgeCheck(corpus, biasDetails, callback){
	biasCheckAbstracted("hedges_hyland2005.txt", corpus, biasDetails, callback);
}

function implicativesCheck(corpus, biasDetails, callback){
	biasCheckAbstracted("implicatives_karttunen1971.txt", corpus, biasDetails, callback);
}

function assertivesCheck(corpus, biasDetails, callback){
	biasCheckAbstracted("assertives_hooper1975.txt", corpus, biasDetails, callback);
}

function factivesCheck(corpus, biasDetails, callback){
	biasCheckAbstracted("factives_hooper1975.txt", corpus, biasDetails, callback);
}

function results(corpus, biasDetails, callback){
	callback(null, parseFloat(biasDetails.termCount/corpus.length).toFixed(4), biasDetails.terms);
}

exports.checkBias = function(corpus, callmeback) {
	//basic - read in hedges and count
	var biasDetails = {terms:[], termCount:0};
	async.waterfall([
	   function(callback){
		   callback(null, corpus, biasDetails);
	   },
	   hedgeCheck,
	   implicativesCheck,
	   assertivesCheck,
	   factivesCheck,
	   results,
	   callmeback
	]);
};