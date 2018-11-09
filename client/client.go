// Copyright 2018 Mathew Odden
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

var HTTP_DEBUG = false

const legacy_uri = "https://ibm-key-protect.edge.bluemix.net/api/v2/keys"

func getEndpoint(regionName string) string {
	return fmt.Sprintf("https://keyprotect.%s.bluemix.net/api/v2/keys", regionName)
}

func PrettyJson(data []byte) []byte {
	var prettified bytes.Buffer
	json.Indent(&prettified, data, "", "  ")
	return prettified.Bytes()
}

type StandardKey map[string]interface{}

func (k StandardKey) Id() string {
	return k["id"].(string)
}

func (k StandardKey) String() string {
	return fmt.Sprintf("StandardKey[Id:%s Payload:%s]", k.Id(), k["payload"])
}

type Authenticator interface {
	AddAuthHeaders(req *http.Request)
}

type KeyPayloadCodec interface {
	EncodePayload(payload []byte) []byte
	DecodePayload(payload string) ([]byte, error)
}

type Client struct {
	*http.Client
	Authenticator
	KeyPayloadCodec
	uri string
}

func (c Client) Request(method string, url string, data io.Reader, headers map[string]string) (*http.Response, []byte) {
	if data != nil && HTTP_DEBUG {
		var bodyBuffer bytes.Buffer
		bodyBuffer.ReadFrom(data)
		log.Printf("Body: %s\n", bodyBuffer.Bytes())
		data = &bodyBuffer
	}

	req, _ := http.NewRequest(method, url, data)

	c.Authenticator.AddAuthHeaders(req)

	req.Header.Add("Accept", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		log.Panicf("error on request: %s\n", err)
	}

	defer resp.Body.Close()
	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Panicf("error reading response body: %s\n", err)
	}

	if (resp.StatusCode / 100) != 2 {
		log.Panicf("http request error: %s %s\n", resp.Status, bodyText)
	}
	return resp, bodyText
}

func (c Client) List() []StandardKey {
	_, bodyText := c.Request("GET", c.uri, nil, nil)

	//log.Printf("debug: %s\n", bodyText)

	var keyList map[string]interface{}

	if err := json.Unmarshal(bodyText, &keyList); err != nil {
		log.Panicln("Error reading key list as JSON")
	}

	keyResources, ok := keyList["resources"]
	if !ok {
		keyResources = make([]interface{}, 0)
	}

	var keys []StandardKey
	for _, val := range keyResources.([]interface{}) {
		key := val.(map[string]interface{})
		keys = append(keys, StandardKey(key))
	}
	return keys
}

func (c Client) Get(id string) StandardKey {
	_, bodyText := c.Request("GET", fmt.Sprintf("%s/%s", c.uri, id), nil, nil)

	var keyBody map[string]interface{}
	if err := json.Unmarshal(bodyText, &keyBody); err != nil {
		log.Panicln("Error reading key body as JSON")
	}

	// apparently, even individual keys are wrapped in collections too...?
	var keys []StandardKey
	for _, val := range keyBody["resources"].([]interface{}) {
		key := val.(map[string]interface{})
		if payload, err := c.KeyPayloadCodec.DecodePayload(key["payload"].(string)); err == nil {
			key["payload"] = payload
		} else {
			fmt.Printf("error while decoding key payload: %s\n", err)
		}
		keys = append(keys, StandardKey(key))
	}

	if len(keys) > 1 {
		log.Println("warning: multiple keys found in GET body")
	}

	return keys[0]
}

func (c Client) parseKeyCollection(collection []byte) []StandardKey {
	var keyBody map[string]interface{}
	if err := json.Unmarshal(collection, &keyBody); err != nil {
		log.Panicln("Error reading key body as JSON")
	}

	// apparently, even individual keys are wrapped in collections too...?
	var keys []StandardKey
	for _, val := range keyBody["resources"].([]interface{}) {
		key := val.(map[string]interface{})
		if rawPayload, ok := key["payload"]; ok {
			if payload, err := c.KeyPayloadCodec.DecodePayload(rawPayload.(string)); err == nil {
				key["payload"] = payload
			} else {
				fmt.Printf("error while decoding key payload: %s\n", err)
			}
		}
		keys = append(keys, StandardKey(key))
	}

	return keys
}

func (c Client) Generate(name string) (StandardKey, error) {

	keyDef := map[string]interface{}{
		"type":        "application/vnd.ibm.kms.key+json",
		"name":        name,
		"extractable": true,
	}

	return c.CreateFromDef(keyDef)
}

func (c Client) CreateFromDef(keyDef map[string]interface{}) (StandardKey, error) {
	requestData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"collectionType":  "application/vnd.ibm.kms.key+json",
			"collectionTotal": 1,
		},
		"resources": []interface{}{
			keyDef,
		},
	}
	var bodyBuffer bytes.Buffer
	json.NewEncoder(&bodyBuffer).Encode(requestData)

	_, bodyText := c.Request("POST", c.uri, &bodyBuffer, nil)

	if keys := c.parseKeyCollection(bodyText); len(keys) >= 1 {
		return keys[0], nil
	} else {
		return nil, fmt.Errorf("error during create: %s", bodyText)
	}
}

func (c Client) Delete(id string) error {
	c.Request("DELETE", fmt.Sprintf("%s/%s", c.uri, id), nil, nil)
	return nil
}

type KPAuthenticator struct {
	IamToken   string
	InstanceId string
}

func (kp KPAuthenticator) AddAuthHeaders(req *http.Request) {
	req.Header.Add("Authorization", kp.IamToken)
	req.Header.Add("Bluemix-Instance", kp.InstanceId)
}

type LegacyAuthenticator struct {
	OrgId    string
	SpaceId  string
	UaaToken string
}

func (la LegacyAuthenticator) AddAuthHeaders(req *http.Request) {
	req.Header.Add("Authorization", la.UaaToken)
	req.Header.Add("Bluemix-Org", la.OrgId)
	req.Header.Add("Bluemix-Space", la.SpaceId)
}

type LegacyPayloadCodec struct{}

func (kp LegacyPayloadCodec) EncodePayload(payload []byte) []byte {
	return payload
}

func (kp LegacyPayloadCodec) DecodePayload(payload string) ([]byte, error) {
	return []byte(payload), nil
}

type KPPayloadCodec struct{}

func (kp KPPayloadCodec) EncodePayload(payload []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(payload))
}

func (kp KPPayloadCodec) DecodePayload(payload string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(payload)
}

func NewLegacyClient(orgId string, spaceId string, uaaToken string) *Client {
	return &Client{
		Client: &http.Client{Timeout: 60 * time.Second},
		Authenticator: LegacyAuthenticator{
			OrgId:    orgId,
			SpaceId:  spaceId,
			UaaToken: uaaToken,
		},
		KeyPayloadCodec: LegacyPayloadCodec{},
		uri:             legacy_uri,
	}
}

func NewKPClient(instanceId string, iamToken string, region string) *Client {
	return &Client{
		Client: &http.Client{Timeout: 60 * time.Second},
		Authenticator: KPAuthenticator{
			IamToken:   iamToken,
			InstanceId: instanceId,
		},
		KeyPayloadCodec: KPPayloadCodec{},
		uri:             getEndpoint(region),
	}
}
