package veritas

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// API version
	API_VERSION  = "v1"
	API_ENDPOINT = "http://api.flxveritas.com"

	// Regions
	REGION_ANY = "any"

	// Log levels
	LOG_TRACE = 3
	LOG_DEBUG = 2
	LOG_WARN  = 1
	LOG_ERROR = 0

	// Response type
	RESPONSETYPE_FETCH_SINGLE = 1
	RESPONSETYPE_FETCH_MULTI  = 2
	RESPONSETYPE_MUTATION     = 3

	// Value types
	VALTYPE_DATA  = 1
	VALTYPE_COUNT = 2
)

var requestTimeout = time.Duration(10 * time.Second)

func NewClient(customerId int, applicationId int, secureToken string) *VeritasClient {
	obj := &VeritasClient{
		customerId:    customerId,
		applicationId: applicationId,
		secureToken:   secureToken,
		logLevel:      LOG_WARN,
	}
	obj.SetVersion(API_VERSION)
	obj.SetEndpoint(API_ENDPOINT)
	obj.SetRegion(REGION_ANY)
	return obj
}

func (v *VeritasClient) Select(db string) {
	v.database = db
}

func (v *VeritasClient) SetVersion(version string) {
	v.version = version
}

func (v *VeritasClient) SetRegion(region string) {
	v.region = region
}

func (v *VeritasClient) SetEndpoint(endpoint string) {
	v.endpoint = endpoint
}

func (v *VeritasClient) SetLogLevel(l int) bool {
	if l < LOG_ERROR || l > LOG_TRACE {
		log.Println("Invalid log level, ignoring update")
		return false
	}
	v.logLevel = l
	return true
}

func (v *VeritasClient) PrintDebug() {
	log.Println(fmt.Sprintf("Veritas client (customer: %d) (app: %d) (database: %s)", v.customerId, v.applicationId, v.database))
}

// Get multi
func (v *VeritasClient) GetMulti(table string, keymap map[string][]string) (*Response, error) {
	// Create object
	outer := NewRequestPayload()
	outer.DefaultDb = v.database
	outer.DefaultTable = table

	// Objects
	for k, v := range keymap {
		object := NewPayloadObjectsKeys()
		object.Key = k
		for _, sk := range v {
			object.Values = append(object.Values, sk)
		}
		outer.Objects = append(outer.Objects, object)
	}

	// To json
	jsonBytes, jsonErr := json.Marshal(outer)
	if jsonErr != nil {
		return nil, jsonErr
	}

	log.Println(string(jsonBytes))

	r := v.newRequest(v, "GET", fmt.Sprintf("data-multi/%s", string(jsonBytes)), VALTYPE_DATA, RESPONSETYPE_FETCH_MULTI)
	res, resErr := r.Execute()
	return res, resErr
}

// Get single
func (v *VeritasClient) GetSingle(table string, key string, subkey string) (*Response, error) {
	r := v.newRequest(v, "GET", fmt.Sprintf("data/%s/%s/%s/%s", v.database, table, key, subkey), VALTYPE_DATA, RESPONSETYPE_FETCH_SINGLE)
	res, resErr := r.Execute()
	return res, resErr
}

// Put single
func (v *VeritasClient) PutSingle(table string, key string, subkey string, value string) (*Response, error) {
	r := v.newRequest(v, "PUT", "data", VALTYPE_DATA, RESPONSETYPE_MUTATION)

	// Create object
	outer := NewRequestPayload()
	outer.DefaultDb = v.database
	outer.DefaultTable = table

	// One object
	object := NewPayloadObjectsKeyValues()
	object.Key = key
	object.Values[subkey] = value
	outer.Objects = append(outer.Objects, object)

	// To json
	bodyBytes, jsonErr := json.Marshal(outer)
	if jsonErr != nil {
		return nil, jsonErr
	}
	if v.logLevel >= LOG_TRACE {
		log.Println(string(bodyBytes))
	}

	r.body = string(bodyBytes)

	res, resErr := r.Execute()
	return res, resErr
}

// Get single count
func (v *VeritasClient) GetSingleCount(table string, key string, subkey string) (*Response, error) {
	r := v.newRequest(v, "GET", fmt.Sprintf("count/%s/%s/%s/%s", v.database, table, key, subkey), VALTYPE_COUNT, RESPONSETYPE_FETCH_SINGLE)
	res, resErr := r.Execute()
	return res, resErr
}

// Increment single count
func (v *VeritasClient) IncrementSingleCount(table string, key string, subkey string, value int) (*Response, error) {
	r := v.newRequest(v, "PUT", "count", VALTYPE_COUNT, RESPONSETYPE_MUTATION)

	// Create object
	outer := NewRequestPayload()
	outer.DefaultDb = v.database
	outer.DefaultTable = table

	// One object
	object := NewPayloadObjectsKeyValues()
	object.Key = key
	object.Values[subkey] = value
	outer.Objects = append(outer.Objects, object)

	// To json
	bodyBytes, jsonErr := json.Marshal(outer)
	if jsonErr != nil {
		return nil, jsonErr
	}
	if v.logLevel >= LOG_TRACE {
		log.Println(string(bodyBytes))
	}

	r.body = string(bodyBytes)

	res, resErr := r.Execute()
	return res, resErr
}

// Sign a request
func (r *Request) signRequest() string {
	// Sha512 hasher
	hasher := sha512.New()

	// Method
	io.WriteString(hasher, r.method)

	// Url
	io.WriteString(hasher, r.getUrl())

	// Token
	io.WriteString(hasher, r.client.secureToken)

	// Content length
	io.WriteString(hasher, fmt.Sprintf("%d", len(r.body)))

	// Content hash
	sha1H := sha1.New()
	io.WriteString(sha1H, r.body)
	sha1Body := fmt.Sprintf("%x", sha1H.Sum(nil))
	io.WriteString(hasher, sha1Body)

	// Done
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// Get url
func (r *Request) getUrl() string {
	return fmt.Sprintf("/%s/%s", r.client.version, r.endpoint)
}

// Request timeout helper
func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, requestTimeout)
}

// Execute request
func (r *Request) Execute() (*Response, error) {
	// Url
	fullUrl := fmt.Sprintf("%s%s", r.client.endpoint, r.getUrl())

	// Create request
	req, reqErr := http.NewRequest(r.method, fullUrl, bytes.NewBuffer([]byte(r.body)))
	if reqErr != nil {
		return nil, reqErr
	}

	// Auth token in header
	signature := r.signRequest()
	req.Header.Set("X-Auth", signature)

	// Content type
	if len(r.body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Route header
	req.Header.Set("X-Veritas-Route", fmt.Sprintf("%s/%d/%d", r.client.region, r.client.applicationId, r.client.customerId))

	// HTTP transport
	transport := http.Transport{
		Dial: dialTimeout,
	}

	// HTTP client
	client := &http.Client{
		Transport: &transport,
	}

	// Execute
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read body
	body, bodyErr := ioutil.ReadAll(resp.Body)
	if bodyErr != nil {
		return nil, bodyErr
	}
	bodyStr := string(body)

	// Debug
	if r.client.logLevel >= LOG_TRACE {
		log.Println(fmt.Sprintf("Response Status: %v", resp.Status))
		log.Println(fmt.Sprintf("Response Headers: %v", resp.Header))
		log.Println(fmt.Sprintf("Response Body: %s", bodyStr))
	}

	// Response
	res := NewResponse(r, bodyStr)

	// Return
	return res, nil
}

// New request
func (v *VeritasClient) newRequest(client *VeritasClient, method string, endpoint string, valType int, respType int) *Request {
	return &Request{
		client:       client,
		endpoint:     endpoint,
		method:       strings.ToUpper(method),
		opts:         v.newRequestOpts(),
		valType:      valType,
		responseType: respType,
	}
}

// Request options (defaults)
func (v *VeritasClient) newRequestOpts() *RequestOpts {
	return &RequestOpts{
		encryption: true,  // Always encrypted by default
		async:      false, // Not sync by default
		redundancy: 1,     // 1 datastore, means 3 replicas
	}
}

type VeritasClient struct {
	customerId    int
	applicationId int
	secureToken   string
	version       string
	database      string
	endpoint      string
	region        string
	logLevel      int
}

type RequestOpts struct {
	encryption bool
	async      bool
	redundancy int
}

type Request struct {
	client       *VeritasClient
	endpoint     string
	method       string
	body         string
	opts         *RequestOpts
	valType      int
	responseType int
}

// Payloads
type IPayloadObjects interface {
	GetKey() string
	GetDbOverride() string
	GetTableOverride() string
	GetValues() interface{}
}

type RequestPayload struct {
	DefaultDb    string        `json:"default_db"`
	DefaultTable string        `json:"default_table"`
	Objects      []interface{} `json:"objects"`
}

type PayloadObjectsKeyValues struct {
	Key           string                 `json:"k"`
	DbOverride    string                 `json:"db_override,omitempty"`
	TableOverride string                 `json:"table_override,omitempty"`
	Values        map[string]interface{} `json:"v"`
}

type PayloadObjectsKeys struct {
	Key           string   `json:"k"`
	DbOverride    string   `json:"db_override,omitempty"`
	TableOverride string   `json:"table_override,omitempty"`
	Values        []string `json:"v"`
}

func NewResponse(req *Request, bodyStr string) *Response {
	obj := &Response{
		RawBody: bodyStr,
		Request: req,
	}
	obj.parse()
	return obj
}

type Response struct {
	Success      bool
	ResponseType int
	RawBody      string
	Request      *Request
	Error        error
	StrValue     string
	IntValue     int64
}

func (r *Response) parse() {
	// Valid body?
	if len(r.RawBody) < 1 {
		if r.Request.client.logLevel >= LOG_WARN {
			log.Println("Empty response body, unable to parse into response")
		}
		return
	}

	// Json
	var data map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(r.RawBody), &data); jsonErr != nil {
		r.Success = false
		r.Error = jsonErr
		return
	}
	if fmt.Sprintf("%s", data["status"]) == "OK" {
		r.Success = true
	}

	// Value extraction
	if data["data"] != nil {
		dataMap := data["data"].(map[string]interface{})
		if r.Request.responseType == RESPONSETYPE_FETCH_SINGLE {
			// Single value responses
			if r.Request.valType == VALTYPE_DATA {
				// One single value
				for _, kv := range dataMap {
					kvm := kv.(map[string]interface{})
					for _, v := range kvm {
						r.StrValue = fmt.Sprintf("%s", v)
						break
					}
				}
			} else if r.Request.valType == VALTYPE_COUNT {
				// One single count
				for _, kv := range dataMap {
					kvm := kv.(map[string]interface{})
					for _, v := range kvm {
						f, fe := strconv.ParseFloat(fmt.Sprintf("%f", v), 64)
						if fe == nil {
							r.IntValue = int64(f)
							break
						}
					}
				}
			}
		} else if r.Request.responseType == RESPONSETYPE_MUTATION {
			// Mutation parsing for success
			if dataMap["acknowledged"] != nil {
				// Ack on async
				r.Success = dataMap["acknowledged"].(bool)
			} else if dataMap["executed"] != nil {
				// Exec on sync
				r.Success = dataMap["executed"].(bool)
			}
		}
	}
}

func (r *Response) DataValue() string {
	if r.Request.responseType != RESPONSETYPE_FETCH_SINGLE || r.Request.valType != VALTYPE_DATA {
		log.Fatal("Can not get data value from non-data response")
	}
	return r.StrValue
}

func (r *Response) CountValue() int64 {
	if r.Request.valType != VALTYPE_COUNT {
		log.Fatal("Can not get count value from non-count response")
	}
	return r.IntValue
}

func NewPayloadObjectsKeyValues() *PayloadObjectsKeyValues {
	return &PayloadObjectsKeyValues{
		Values: make(map[string]interface{}),
	}
}

func NewPayloadObjectsKeys() *PayloadObjectsKeys {
	return &PayloadObjectsKeys{
		Values: make([]string, 0),
	}
}

func NewRequestPayload() *RequestPayload {
	return &RequestPayload{}
}

func (o *PayloadObjectsKeyValues) GetKey() string {
	return o.Key
}

func (o *PayloadObjectsKeyValues) GetValues() interface{} {
	return o.Values
}

func (o *PayloadObjectsKeyValues) GetDbOverride() string {
	return o.DbOverride
}

func (o *PayloadObjectsKeyValues) GetTableOverride() string {
	return o.TableOverride
}

func (o *PayloadObjectsKeys) GetKey() string {
	return o.Key
}

func (o *PayloadObjectsKeys) GetValues() interface{} {
	return o.Values
}

func (o *PayloadObjectsKeys) GetDbOverride() string {
	return o.DbOverride
}

func (o *PayloadObjectsKeys) GetTableOverride() string {
	return o.TableOverride
}
