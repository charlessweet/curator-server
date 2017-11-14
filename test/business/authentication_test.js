var assert = require('assert')
var auth = require('../../business/Authentication.js')
describe("/business/Authentication", function(){
	describe("generatePasswordHash", function(){
		it('should match password hash with known hash value', function(){
			assert.equal(auth.generatePasswordHash("this is my password", "this is some salt"), "b8c36b2719cb62a8c5f52bd9513ef528e3d6f37cd98cbf63d04185def85225f9")
		})
	})
})