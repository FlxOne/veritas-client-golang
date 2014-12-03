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
	"net/http"
)

const (
	// API version
	API_VERSION  = "v1"
	API_ENDPOINT = "http://api.flxveritas.com"

	// Regions
	REGION_ANY = "any"
)

func NewClient(customerId int, applicationId int, secureToken string) *VeritasClient {
	obj := &VeritasClient{
		customerId:    customerId,
		applicationId: applicationId,
		secureToken:   secureToken,
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

func (v *VeritasClient) PrintDebug() {
	log.Println(fmt.Sprintf("Veritas client (customer: %d) (app: %d) (database: %s)", v.customerId, v.applicationId, v.database))
}

// Get single
func (v *VeritasClient) GetSingle(table string, key string, subkey string) (interface{}, error) {
	r := v.newRequest(v, "GET", fmt.Sprintf("data/%s/%s/%s/%s", v.database, table, key, subkey))
	log.Println(r.Execute())
	return nil, nil
}

// Put single
func (v *VeritasClient) PutSingle(table string, key string, subkey string, value string) (interface{}, error) {
	r := v.newRequest(v, "PUT", "data")

	// Create object
	outer := &RequestPayload{}
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
	log.Println(string(bodyBytes))

	r.body = string(bodyBytes)
	log.Println(r.Execute())

	return nil, nil
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

// Execute request
func (r *Request) Execute() (string, error) {
	// Url
	fullUrl := fmt.Sprintf("%s%s", r.client.endpoint, r.getUrl())

	// Create request
	req, reqErr := http.NewRequest(r.method, fullUrl, bytes.NewBuffer([]byte(r.body)))
	if reqErr != nil {
		return "", reqErr
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

	// Execute
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))

	// Return
	return "", nil
}

// New request
func (v *VeritasClient) newRequest(client *VeritasClient, method string, endpoint string) *Request {
	return &Request{
		client:   client,
		endpoint: endpoint,
		method:   method,
		opts:     v.newRequestOpts(),
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
}

type RequestOpts struct {
	encryption bool
	async      bool
	redundancy int
}

type Request struct {
	client   *VeritasClient
	endpoint string
	method   string
	body     string
	opts     *RequestOpts
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
	Key           string            `json:"k"`
	DbOverride    string            `json:"db_override"`
	TableOverride string            `json:"table_override"`
	Values        map[string]string `json:"v"`
}

func NewPayloadObjectsKeyValues() *PayloadObjectsKeyValues {
	return &PayloadObjectsKeyValues{
		Values: make(map[string]string),
	}
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

type PayloadObjectsKeys struct {
	Key           string
	DbOverride    string
	TableOverride string
	Values        []string
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
