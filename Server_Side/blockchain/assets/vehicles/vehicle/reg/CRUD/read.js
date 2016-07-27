var request = require('request');
var reload = require('require-reload')(require),
    configFile = reload(__dirname+'/../../../../../../configurations/configuration.js');
var tracing = require(__dirname+'/../../../../../../tools/traces/trace.js');

var read = function (req,res)
{	
	var v5cID = req.params.v5cID;
	
	tracing.create('ENTER', 'GET blockchain/assets/vehicles/vehicle/'+v5cID+'/reg', {});
	configFile = reload(__dirname+'/../../../../../../configurations/configuration.js');
	if(typeof req.cookies.user != "undefined")
	{
		req.session.user = req.cookies.user;
	}
	
	var querySpec =					{
										"jsonrpc": "2.0",
										"method": "query",
										"params": {
										    "type": 1,
											"chaincodeID": {
												"name": configFile.config.vehicle_name
											},
											"ctorMsg": {
											  "function": "get_vehicle_details",
											  "args": [
											  		v5cID
											  ]
											},
											"secureContext": req.session.user,
										},
										"id": 123
									};
									


	var options = 	{
					url: configFile.config.api_ip+':'+configFile.config.api_port_external+'/chaincode',
					method: "POST", 
					body: querySpec,
					json: true
				}
	
	request(options, function(error, response, body)
	{
		
		console.log("Reg update read", body);
		
		if (!error && response.statusCode == 200)
		{
			var result = {}
			var vehicle = JSON.parse(body.result.message);
			result.message = vehicle.reg;
			tracing.create('EXIT', 'GET blockchain/assets/vehicles/vehicle/'+v5cID+'/reg', result);
			res.send(result)
		}
		else 
		{
			res.status(400)
			var error = {}
			error.message = 'Unable to read reg'
			error.v5cID = v5cID;
			error.error = true;
			tracing.create('ERROR', 'GET blockchain/assets/vehicles/vehicle/'+v5cID+'/reg', error)
			res.send(error)
		}
	});
}

exports.read = read;