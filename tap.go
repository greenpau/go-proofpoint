// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proofpoint

import (
	"encoding/json"
	"fmt"
)

// GetData returns data by providing service name and operation, as well as
// other options.
func (c *Client) GetData(serviceName, serviceOperation string, opts map[string]interface{}) ([]string, error) {
	resp := []string{}
	var clicks []*Click
	var messages []*Message
	var err error
	switch serviceName {
	case "siem":
		switch serviceOperation {
		case "issues":
			clicks, messages, err = c.GetSiemIssues(opts)
		case "all":
			clicks, messages, err = c.GetSiemAll(opts)
		case "blocked_messages":
			messages, err = c.GetSiemBlockedMessages(opts)
		case "delivered_messages":
			messages, err = c.GetSiemDeliveredMessages(opts)
		case "permitted_clicks":
			clicks, err = c.GetSiemPermittedClicks(opts)
		case "blocked_clicks":
			clicks, err = c.GetSiemBlockedClicks(opts)
		case "":
			return nil, fmt.Errorf("service operation is empty")
		default:
			return nil, fmt.Errorf("unsupported service operation: %s", serviceOperation)
		}
		if err != nil {
			return nil, fmt.Errorf("failed request %s/%s: %s", serviceName, serviceOperation, err)
		}
		for _, item := range clicks {
			itemJSON, err := json.Marshal(item)
			if err != nil {
				return nil, fmt.Errorf("failed processing clicks: %s", err)
			}
			resp = append(resp, string(itemJSON))
		}
		for _, item := range messages {
			itemJSON, err := json.Marshal(item)
			if err != nil {
				return nil, fmt.Errorf("failed processing messages: %s", err)
			}
			resp = append(resp, string(itemJSON))
		}
	case "":
		return nil, fmt.Errorf("service name is empty")
	default:
		return nil, fmt.Errorf("unsupported service name: %s", serviceName)
	}
	return resp, nil
}
