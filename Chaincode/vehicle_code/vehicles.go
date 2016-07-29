package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"fabric/core/chaincode/shim"
	"encoding/json"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"io/ioutil"
	"math/rand"
	//	"regexp" //regex for GO...used later when chacking values -> TODO
)

//==============================================================================================================================
//	 Participant types - Each participant type is mapped to an integer which we use to compare to the value stored in a
//						 user's eCert
//==============================================================================================================================
const GOVERNMENT = 1
const MANUFACTURER = 2
const BUYER = 3
const MANUFACTURER_BANK = 4
const BUYER_BANK = 5
const SHIPPER = 6
const PRODUCT = 7


//==============================================================================================================================
//	 Status types - Asset lifecycle is broken down into 5 statuses, this is part of the business logic to determine what can 
//					be done to the vehicle at points in it's lifecycle
//==============================================================================================================================
const STATE_SALESCONTRACT = 0
const STATE_ACCREDITIVE = 1
const STATE_CHECK_ACCREDITIVE = 2
const STATE_MANUFACTURE = 3
const STATE_SHIPPING = 4
const STATE_PAYMENT = 5
const STATE_INUSE = 6
const STATE_SCRAPPED = 7

//==============================================================================================================================
//	 Structure Definitions 
//==============================================================================================================================
//	Chaincode - A blank struct for use with Shim (A HyperLedger included go file used for get/put state
//				and other HyperLedger functions)
//==============================================================================================================================
type  SimpleChaincode struct {
}

//==============================================================================================================================
//	Vehicle - Defines the structure for a car object. JSON on right tells it what JSON fields to map to
//			  that element when reading a JSON object into the struct e.g. JSON make -> Struct Make.
//==============================================================================================================================
//noinspection GoStructTag
type Product struct {
	Product_Id       string `json:pid`
	CheckId          string `json:checksum`
	Manufacturer     string `json:manufacturer`
	Owner            string `json:owner`
	Origin           string `json:origin`
	Current_location string `json:current_location`
	Destination      string `json:destination`
	Route            string `json:route`
	State            int `json:state`
	Price            float32 `json:price`
	Currency         string `json:currency`
	Width            float32 `json:width`
	Height           float32 `json:height`
	Weight           float32 `json:weight`
	Sales_contract   byte `json:contract`
}


//==============================================================================================================================
//	V5C Holder - Defines the structure that holds all the v5cIDs for vehicles that have been created.
//				Used as an index when querying all vehicles.
//==============================================================================================================================

type Product_Id_Holder struct {
	ProductIds []int `json:"productIds"`
}

//==============================================================================================================================
//	ECertResponse - Struct for storing the JSON response of retrieving an ECert. JSON OK -> Struct OK
//==============================================================================================================================
type ECertResponse struct {
	OK    string `json:"OK"`
	Error string `json:"Error"`
}

//==============================================================================================================================
//	Init Function - Called when the user deploys the chaincode																	
//==============================================================================================================================
func (t *SimpleChaincode) Init(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {

	//Args
	//				0
	//			peer_address


	var ProductIds Product_Id_Holder

	bytes, err := json.Marshal(ProductIds)

	if err != nil {
		return nil, errors.New("Error creating Product_Id_Holder record")
	}

	err = stub.PutState("pids", bytes)

	err = stub.PutState("Peer_Address", []byte(args[0]))
	if err != nil {
		return nil, errors.New("Error storing peer address")
	}

	return nil, nil
}

//==============================================================================================================================
//	 General Functions
//==============================================================================================================================
//	 get_ecert - Takes the name passed and calls out to the REST API for HyperLedger to retrieve the ecert
//				 for that user. Returns the ecert as retrived including html encoding.
//==============================================================================================================================
func (t *SimpleChaincode) get_ecert(stub *shim.ChaincodeStub, name string) ([]byte, error) {

	var cert ECertResponse

	peer_address, err := stub.GetState("Peer_Address")
	if err != nil {
		return nil, errors.New("Error retrieving peer address")
	}

	response, err := http.Get("http://" + string(peer_address) + "/registrar/" + name + "/ecert")        // Calls out to the HyperLedger REST API to get the ecert of the user with that name

	fmt.Println("HTTP RESPONSE", response)

	if err != nil {
		return nil, errors.New("Error calling ecert API")
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)                                        // Read the response from the http callout into the variable contents

	fmt.Println("HTTP BODY:", string(contents))

	if err != nil {
		return nil, errors.New("Could not read body")
	}

	err = json.Unmarshal(contents, &cert)

	if err != nil {
		return nil, errors.New("Could not retrieve ecert for user: " + name)
	}

	fmt.Println("CERT OBJECT:", cert)

	if cert.Error != "" {
		fmt.Println("GET ECERT ERRORED: ", cert.Error); return nil, errors.New(cert.Error)
	}

	return []byte(string(cert.OK)), nil
}

//==============================================================================================================================
//	 get_caller - Retrieves the username of the user who invoked the chaincode.
//				  Returns the username as a string.
//==============================================================================================================================

func (t *SimpleChaincode) get_username(stub *shim.ChaincodeStub) (string, error) {

	bytes, err := stub.GetCallerCertificate();
	if err != nil {
		return "", errors.New("Couldn't retrieve caller certificate")
	}
	x509Cert, err := x509.ParseCertificate(bytes); // Extract Certificate from result of GetCallerCertificate
	if err != nil {
		return "", errors.New("Couldn't parse certificate")
	}

	return x509Cert.Subject.CommonName, nil
}

//==============================================================================================================================
//	 check_affiliation - Takes an ecert as a string, decodes it to remove html encoding then parses it and checks the
// 				  		certificates common name. The affiliation is stored as part of the common name.
//==============================================================================================================================

func (t *SimpleChaincode) check_affiliation(stub *shim.ChaincodeStub, cert string) (int, error) {

	decodedCert, err := url.QueryUnescape(cert); // make % etc normal //

	if err != nil {
		return -1, errors.New("Could not decode certificate")
	}

	pem, _ := pem.Decode([]byte(decodedCert))                                        // Make Plain text   //

	x509Cert, err := x509.ParseCertificate(pem.Bytes); // Extract Certificate from argument //

	if err != nil {
		return -1, errors.New("Couldn't parse certificate")
	}

	cn := x509Cert.Subject.CommonName

	res := strings.Split(cn, "\\")

	affiliation, _ := strconv.Atoi(res[2])

	return affiliation, nil
}

//==============================================================================================================================
//	 get_caller_data - Calls the get_ecert and check_role functions and returns the ecert and role for the
//					 name passed.
//==============================================================================================================================

func (t *SimpleChaincode) get_caller_data(stub *shim.ChaincodeStub) (string, int, error) {

	user, err := t.get_username(stub)
	if err != nil {
		return "", -1, err
	}

	ecert, err := t.get_ecert(stub, user);
	if err != nil {
		return "", -1, err
	}

	affiliation, err := t.check_affiliation(stub, string(ecert));
	if err != nil {
		return "", -1, err
	}

	return user, affiliation, nil
}

//==============================================================================================================================
//	 retrieve_v5c - Gets the state of the data at v5cID in the ledger then converts it from the stored 
//					JSON into the Vehicle struct for use in the contract. Returns the Vehcile struct.
//					Returns empty v if it errors.
//==============================================================================================================================
func (t *SimpleChaincode) retrieve_product(stub *shim.ChaincodeStub, productId string) (Product, error) {

	var product Product

	bytes, err := stub.GetState(productId);

	if err != nil {
		fmt.Printf("RETRIEVE_PRODUCT: Failed to invoke chaincode: %s", err); return product, errors.New("RETRIEVE_V5C: Error retrieving vehicle with pid = " + productId)
	}

	err = json.Unmarshal(bytes, &product);

	if err != nil {
		fmt.Printf("RETRIEVE_PRODUCT: Corrupt product record " + string(bytes) + ": %s", err); return product, errors.New("RETRIEVE_PRODUCT: Corrupt product record" + string(bytes))
	}

	return product, nil
}

//==============================================================================================================================
// save_changes - Writes to the ledger the Vehicle struct passed in a JSON format. Uses the shim file's 
//				  method 'PutState'.
//==============================================================================================================================
func (t *SimpleChaincode) save_changes(stub *shim.ChaincodeStub, product Product) (bool, error) {

	bytes, err := json.Marshal(product)

	if err != nil {
		fmt.Printf("SAVE_CHANGES: Error converting vehicle record: %s", err); return false, errors.New("Error converting vehicle record")
	}

	err = stub.PutState(product.Product_Id, bytes)

	if err != nil {
		fmt.Printf("SAVE_CHANGES: Error storing vehicle record: %s", err); return false, errors.New("Error storing vehicle record")
	}

	return true, nil
}
//==============================================================================================================================
// createRandomId - Creates a random id for the product
//
//==============================================================================================================================

func (t *SimpleChaincode) createRandomId(stub *shim.ChaincodeStub) (int) {
	var randomId = 0
	var low = 100000000
	var high = 999999999
	for {
		randomId = rand.Intn(high - low) + low
		if (t.isRandomIdUnused(stub, randomId)) {
			break
		}
	}
	//TODO in createProduct() die ID zur ID-Liste hinzufügen

	return randomId
}

//==============================================================================================================================
// isRandomIdUnused - Checks if the randomly created id is already used by another product.
//
//==============================================================================================================================
func (t *SimpleChaincode) isRandomIdUnused(stub *shim.ChaincodeStub, randomId int) (bool) {
	usedIds := make([]int, 500)
	usedIds = t.getAllUsedProductIds(stub)
	for _, id := range usedIds {
		if (id == randomId) {
			return false
		}
	}

	return true
}
//==============================================================================================================================
// isRandomIdUnused - Checks if the randomly created id is already used by another product.
//
//==============================================================================================================================
func (t *SimpleChaincode) getAllUsedProductIds(stub *shim.ChaincodeStub) (bool) {

	usedIds := make([]int, 500)

	bytes, err := stub.GetState("productId")

	if err != nil {
		return nil, errors.New("Unable to get productIds")
	}

	var productIds Product_Id_Holder
	err = json.Unmarshal(bytes, &productIds)

	if err != nil {
		return nil, errors.New("Invalid JSON")
	}
	var product Product

	for i, pid := range productIds.ProductIds {

		product, err = t.retrieve_product(stub, pid)

		if err != nil {
			return nil, errors.New("Failed to retrieve pid")
		}
		if (product != nil || product != "[]") {
			usedIds[i] = product.Product_Id
		}
	}

	return usedIds
}
//==============================================================================================================================
//	 Router Functions
//==============================================================================================================================
//	Invoke - Called on chaincode invoke. Takes a function name passed and calls that function. Converts some
//		  initial arguments passed to other things for use in the called function e.g. name -> ecert
//==============================================================================================================================
func (t *SimpleChaincode) Invoke(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {

	caller1, caller2, caller1_affiliation, caller2_affiliation, destination, price, currency, contract, err := t.get_caller_data(stub)

	if err != nil {
		return nil, errors.New("Error retrieving caller information")
	}

	if function == "create_product" {
		return t.create_product(stub, caller1, caller2, caller1_affiliation, caller2_affiliation, destination, price, currency, contract, args[0])
	} else {
		// If the function is not a create then there must be a car so we need to retrieve the car.

		argPos := 1

		if function == "scrap_vehicle" {
			// If its a scrap vehicle then only two arguments are passed (no update value) all others have three arguments and the v5cID is expected in the last argument
			argPos = 0
		}

		product, err := t.retrieve_product(stub, args[argPos])

		if err != nil {
			fmt.Printf("INVOKE: Error retrieving v5c: %s", err); return nil, errors.New("Error retrieving v5c")
		}

		if strings.Contains(function, "update") == false           &&
			function != "scrap_vehicle" {
			//If the function is not an update or a scrappage it must be a transfer so we need to get the ecert of the recipient.

			ecert, err := t.get_ecert(stub, args[0]);

			if err != nil {
				return nil, err
			}

			rec_affiliation, err := t.check_affiliation(stub, string(ecert));

			if err != nil {
				return nil, err
			}
			fmt.Printf(rec_affiliation) //TODO remove
			fmt.Printf(product)//TODO remove
			//if function == "manufacturer_to_buyer" {
			//	return t.manufacturer_to_buyer(stub, v, caller, caller_affiliation, args[0], rec_affiliation)
			//} else if function == "manufacturer_to_bank" {
			//	return t.manufacturer_to_bank(stub, v, caller, caller_affiliation, args[0], rec_affiliation)
			//} else if function == "buyer_to_buyer" {
			//	return t.buyer_to_buyer(stub, v, caller, caller_affiliation, args[0], rec_affiliation)
			//} else if function == "private_to_lease_company" {
			//	return t.private_to_lease_company(stub, v, caller, caller_affiliation, args[0], rec_affiliation)
			//} else if function == "lease_company_to_private" {
			//	return t.lease_company_to_private(stub, v, caller, caller_affiliation, args[0], rec_affiliation)
			//} else if function == "private_to_scrap_merchant" {
			//	return t.private_to_scrap_merchant(stub, v, caller, caller_affiliation, args[0], rec_affiliation)
			//}

			//} else if function == "update_make" {
			//	return t.update_make(stub, v, caller, caller_affiliation, args[0])
			//} else if function == "update_model" {
			//	return t.update_model(stub, v, caller, caller_affiliation, args[0])
			//} else if function == "update_registration" {
			//	return t.update_registration(stub, v, caller, caller_affiliation, args[0])
			//} else if function == "update_colour" {
			//	return t.update_colour(stub, v, caller, caller_affiliation, args[0])
			//} else if function == "scrap_vehicle" {
			//	return t.scrap_vehicle(stub, v, caller, caller_affiliation)
		}

		return nil, errors.New("Function of that name doesn't exist.")

	}
}
//=================================================================================================================================	
//	Query - Called on chaincode query. Takes a function name passed and calls that function. Passes the
//  		initial arguments passed are passed on to the called function.
//=================================================================================================================================	
func (t *SimpleChaincode) Query(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {

	caller, caller_affiliation, err := t.get_caller_data(stub)

	if err != nil {
		fmt.Printf("QUERY: Error retrieving caller details %s", err); return nil, errors.New("QUERY: Error retrieving caller details")
	}

	if function == "get_vehicle_details" {

		if len(args) != 1 {
			fmt.Printf("Incorrect number of arguments passed: Should be 1 but is %s", args);
			return nil, errors.New("QUERY: Incorrect number of arguments passed")
		}

		v, err := t.retrieve_product(stub, args[0])
		if err != nil {
			fmt.Printf("QUERY: Error retrieving v5c: %s", err); return nil, errors.New("QUERY: Error retrieving v5c " + err.Error())
		}

		return t.get_vehicle_details(stub, v, caller, caller_affiliation)

	} else if function == "get_vehicles" {
		return t.get_vehicles(stub, caller, caller_affiliation)
	}
	return nil, errors.New("Received unknown function invocation")
}

//=================================================================================================================================
//	 Create Function
//=================================================================================================================================									
//	 Create Vehicle - Creates the initial JSON for the vehcile and then saves it to the ledger.
// caller1 : Seller - caller2 : Buyer
//=================================================================================================================================
func (t *SimpleChaincode) create_product(stub *shim.ChaincodeStub, caller1 string, caller2 string, caller1_affiliation int, caller2_affiliation int, product_destination string, product_price float32, product_currency string, contract byte) ([]byte, error) {

	var product Product
	var productId = t.createRandomId(stub)

	if (caller1_affiliation == 2 && caller2_affiliation == 3) {
		pid := "\"productId\":\"" + productId + "\", "                                                       // Variables to define the JSON
		checkId := "\"checksum\":\"UNDEFINED\", "
		manufacturer := "\"manufacturer\":\"" + caller1 + "\", "
		owner := "\"owner\":\"" + caller1 + "\", "
		origin := "\"origin\":\"UNDEFINED\", "
		current_location := "\"current_location\":\"UNDEFINED\", "
		destination := "\"destination\":\"" + product_destination + "\", "
		route := "\"route\":\"UNDEFINED\", "
		state := "\"state\":0, "
		price := "\"price\":\"" + product_price + "\","
		currency := "\"currency\":\"" + product_currency + "\","
		width := "\"width\":\"UNDEFINED\","
		height := "\"height\":\"UNDEFINED\","
		weight := "\"weight\":\"UNDEFINED\","
		sales_contract := "\"sales_contract\":\"" + contract + "\""

		product_json := "{" + pid + checkId + manufacturer + owner + origin + current_location + destination + route + state + price + currency + width + height + weight + sales_contract + "}"        // Concatenates the variables to create the total JSON object


		var err = json.Unmarshal([]byte(product_json), &product)                                                        // Convert the JSON defined above into a vehicle object for go

		if err != nil {
			return nil, errors.New("Invalid JSON object")
		}

		record, err := stub.GetState(product.V5cID)                                                                // If not an error then a record exists so cant create a new car with this V5cID as it must be unique

		if record != nil {
			return nil, errors.New("Vehicle already exists")
		}

		if caller_affiliation != GOVERNMENT {
			// Only the regulator can create a new v5c

			return nil, errors.New("Permission Denied")
		}

		_, err = t.save_changes(stub, product)

		if err != nil {
			fmt.Printf("CREATE_VEHICLE: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
		}

		bytes, err := stub.GetState("v5cIDs")

		if err != nil {
			return nil, errors.New("Unable to get v5cIDs")
		}

		var v5cIDs Product_Id_Holder

		err = json.Unmarshal(bytes, &v5cIDs)

		if err != nil {
			return nil, errors.New("Corrupt V5C_Holder record")
		}

		v5cIDs.ProductIds = append(v5cIDs.ProductIds, productId)

		bytes, err = json.Marshal(v5cIDs)

		if err != nil {
			fmt.Print("Error creating V5C_Holder record")
		}

		err = stub.PutState("v5cIDs", bytes)

		if err != nil {
			return nil, errors.New("Unable to put the state")
		}
	}
	return nil, nil

}

//=================================================================================================================================
//	 Transfer Functions
//=================================================================================================================================
//	 authority_to_manufacturer
//=================================================================================================================================
//noinspection GoPlaceholderCount
func (t *SimpleChaincode) manufacturer_to_buyer(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {

	if v.Status == STATE_SALESCONTRACT        &&
		v.Owner == caller                        &&
		caller_affiliation == GOVERNMENT                &&
		recipient_affiliation == MANUFACTURER                &&
		v.Scrapped == false {
		// If the roles and users are ok

		v.Owner = recipient_name                // then make the owner the new owner
		v.Status = STATE_ACCREDITIVE                        // and mark it in the state of manufacture

	} else {
		// Otherwise if there is an error

		fmt.Printf("AUTHORITY_TO_MANUFACTURER: Permission Denied");
		return nil, errors.New("Permission Denied")

	}

	_, err := t.save_changes(stub, v)                                                // Write new state

	if err != nil {
		fmt.Printf("AUTHORITY_TO_MANUFACTURER: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil                                                                        // We are Done

}

//=================================================================================================================================
//	 manufacturer_to_private
//=================================================================================================================================
func (t *SimpleChaincode) manufacturer_to_bank(stub *shim.ChaincodeStub, product Product, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {

	if product.Make == "UNDEFINED" ||
		product.Name == "UNDEFINED" ||
		product.Reg == "UNDEFINED" ||
		product.Colour == "UNDEFINED" ||
		product.VIN == 0 {
		//If any part of the car is undefined it has not bene fully manufacturered so cannot be sent
		fmt.Printf("MANUFACTURER_TO_PRIVATE: Product not fully defined! Product: %s", product)
		return nil, errors.New("Car not fully defined")
	}

	if product.Status == STATE_ACCREDITIVE        &&
		product.Owner == caller                                &&
		caller_affiliation == MANUFACTURER                        &&
		recipient_affiliation == BUYER                &&
		product.Scrapped == false {

		product.Owner = recipient_name
		product.Status = STATE_CHECK_ACCREDITIVE

	} else {
		return nil, errors.New("Permission denied")
	}

	_, err := t.save_changes(stub, product)

	if err != nil {
		fmt.Printf("MANUFACTURER_TO_PRIVATE: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 private_to_private
//=================================================================================================================================
func (t *SimpleChaincode) buyer_to_buyer(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {

	if v.Status == STATE_CHECK_ACCREDITIVE        &&
		v.Owner == caller                                        &&
		caller_affiliation == BUYER                        &&
		recipient_affiliation == BUYER                        &&
		v.Scrapped == false {

		v.Owner = recipient_name

	} else {

		return nil, errors.New("Permission denied")

	}

	_, err := t.save_changes(stub, v)

	if err != nil {
		fmt.Printf("PRIVATE_TO_PRIVATE: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 private_to_lease_company
//=================================================================================================================================
func (t *SimpleChaincode) private_to_lease_company(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {

	if v.Status == STATE_CHECK_ACCREDITIVE        &&
		v.Owner == caller                                        &&
		caller_affiliation == BUYER                        &&
		recipient_affiliation == MANUFACTURER_BANK                        &&
		v.Scrapped == false {

		v.Owner = recipient_name

	} else {
		return nil, errors.New("Permission denied")
	}

	_, err := t.save_changes(stub, v)
	if err != nil {
		fmt.Printf("PRIVATE_TO_LEASE_COMPANY: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 lease_company_to_private
//=================================================================================================================================
func (t *SimpleChaincode) lease_company_to_private(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {

	if v.Status == STATE_CHECK_ACCREDITIVE        &&
		v.Owner == caller                                        &&
		caller_affiliation == MANUFACTURER_BANK                        &&
		recipient_affiliation == BUYER                        &&
		v.Scrapped == false {

		v.Owner = recipient_name

	} else {
		return nil, errors.New("Permission denied")
	}

	_, err := t.save_changes(stub, v)
	if err != nil {
		fmt.Printf("LEASE_COMPANY_TO_PRIVATE: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 private_to_scrap_merchant
//=================================================================================================================================
func (t *SimpleChaincode) private_to_scrap_merchant(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, recipient_name string, recipient_affiliation int) ([]byte, error) {

	if v.Status == STATE_CHECK_ACCREDITIVE        &&
		v.Owner == caller                                        &&
		caller_affiliation == BUYER                        &&
		recipient_affiliation == BUYER_BANK                        &&
		v.Scrapped == false {

		v.Owner = recipient_name
		v.Status = STATE_SHIPPING

	} else {

		return nil, errors.New("Permission denied")

	}

	_, err := t.save_changes(stub, v)

	if err != nil {
		fmt.Printf("PRIVATE_TO_SCRAP_MERCHANT: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}


//=================================================================================================================================
//	 update_registration
//=================================================================================================================================
func (t *SimpleChaincode) update_registration(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, new_value string) ([]byte, error) {

	if v.Owner == caller                        &&
		caller_affiliation != BUYER_BANK        &&
		v.Scrapped == false {

		v.Reg = new_value

	} else {
		return nil, errors.New("Permission denied")
	}

	_, err := t.save_changes(stub, v)

	if err != nil {
		fmt.Printf("UPDATE_REGISTRATION: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 update_colour
//=================================================================================================================================
func (t *SimpleChaincode) update_colour(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, new_value string) ([]byte, error) {

	if v.Owner == caller                                &&
		caller_affiliation == MANUFACTURER                        &&/*((v.Owner				== caller			&&
			caller_affiliation	== MANUFACTURER)		||
			caller_affiliation	== AUTHORITY)			&&*/
		v.Scrapped == false {

		v.Colour = new_value
	} else {

		return nil, errors.New("Permission denied")
	}

	_, err := t.save_changes(stub, v)

	if err != nil {
		fmt.Printf("UPDATE_COLOUR: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 update_make
//=================================================================================================================================
func (t *SimpleChaincode) update_make(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, new_value string) ([]byte, error) {

	if v.Status == STATE_ACCREDITIVE        &&
		v.Owner == caller                                &&
		caller_affiliation == MANUFACTURER                        &&
		v.Scrapped == false {

		v.Make = new_value
	} else {

		return nil, errors.New("Permission denied")

	}

	_, err := t.save_changes(stub, v)

	if err != nil {
		fmt.Printf("UPDATE_MAKE: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 update_model
//=================================================================================================================================
func (t *SimpleChaincode) update_model(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int, new_value string) ([]byte, error) {

	if v.Status == STATE_ACCREDITIVE        &&
		v.Owner == caller                                &&
		caller_affiliation == MANUFACTURER                        &&
		v.Scrapped == false {

		v.Name = new_value

	} else {
		return nil, errors.New("Permission denied")
	}

	_, err := t.save_changes(stub, v)

	if err != nil {
		fmt.Printf("UPDATE_MODEL: Error saving changes: %s", err); return nil, errors.New("Error saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 scrap_vehicle
//=================================================================================================================================
func (t *SimpleChaincode) scrap_vehicle(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int) ([]byte, error) {

	if v.Status == STATE_SHIPPING        &&
		v.Owner == caller                                &&
		caller_affiliation == BUYER_BANK                &&
		v.Scrapped == false {

		v.Scrapped = true

	} else {
		return nil, errors.New("Permission denied")
	}

	_, err := t.save_changes(stub, v)

	if err != nil {
		fmt.Printf("SCRAP_VEHICLE: Error saving changes: %s", err); return nil, errors.New("SCRAP_VEHICLError saving changes")
	}

	return nil, nil

}

//=================================================================================================================================
//	 Read Functions
//=================================================================================================================================
//	 get_vehicle_details
//=================================================================================================================================
func (t *SimpleChaincode) get_vehicle_details(stub *shim.ChaincodeStub, v Product, caller string, caller_affiliation int) ([]byte, error) {

	bytes, err := json.Marshal(v)

	if err != nil {
		return nil, errors.New("GET_VEHICLE_DETAILS: Invalid vehicle object")
	}

	if v.Owner == caller ||
		caller_affiliation == GOVERNMENT {

		return bytes, nil
	} else {
		return nil, errors.New("Permission Denied")
	}

}

//=================================================================================================================================
//	 get_vehicle_details
//=================================================================================================================================

func (t *SimpleChaincode) get_vehicles(stub *shim.ChaincodeStub, caller string, caller_affiliation int) ([]byte, error) {

	bytes, err := stub.GetState("v5cIDs")

	if err != nil {
		return nil, errors.New("Unable to get v5cIDs")
	}

	var v5cIDs Product_Id_Holder

	err = json.Unmarshal(bytes, &v5cIDs)

	if err != nil {
		return nil, errors.New("Corrupt V5C_Holder")
	}

	result := "["

	var temp []byte
	var v Product

	for _, v5c := range v5cIDs.ProductIds {

		v, err = t.retrieve_product(stub, v5c)

		if err != nil {
			return nil, errors.New("Failed to retrieve V5C")
		}

		temp, err = t.get_vehicle_details(stub, v, caller, caller_affiliation)

		if err == nil {
			result += string(temp) + ","
		}
	}

	if len(result) == 1 {
		result = "[]"
	} else {
		result = result[:len(result) - 1] + "]"
	}

	return []byte(result), nil
}

//=================================================================================================================================
//	 Main - main - Starts up the chaincode
//=================================================================================================================================
func main() {

	err := shim.Start(new(SimpleChaincode))

	if err != nil {
		fmt.Printf("Error starting Chaincode: %s", err)
	}
}
