/**
 * http://usejsdoc.org/
 */
var bias = require("./bias.js");

function printResults(biases){
	console.log(biases);
}

bias.checkBias("this is a huge test", printResults);
//weressetwortedidatandeze:3a94e2d97703970db94498fd684cb95b68004adf
var b64 = new Buffer("weressetwortedidatandeze" + ":" + "3a94e2d97703970db94498fd684cb95b68004adf").toString("base64");
console.log("Basic " + b64);