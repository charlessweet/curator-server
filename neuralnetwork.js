function Neuron(inputValue, weightValue, biasValue){
	var cellSum = 0;
	var input = inputValue;
	var weight = weightValue;
	var bias = biasValue;
	var activation = function(x){
		return Math.max([0,x]);
	};
	
	var forward = function(){
		var rate = 0;
		this.cellSum = this.input + this.weight + this.bias;
		rate = activation(this.cellSum);
		return rate;
	};
}

function NeuralNetworkLayer(){
	var inputs = [];
	var feedforward = function(){
		var outputs = [];
		for(var i = 0; i < inputs.length; i++){
			outputs.push(inputs[i].forward());
		}
		return outputs;
	};
	
	var initialize = function(inputValues, weightValues){
		//build input layer
		for(var i = 0; i < inputValues.length; i++){
			this.nodes.push(new Neuron(inputValues[i], weightValues[i], 0));			
		}
	};
}
