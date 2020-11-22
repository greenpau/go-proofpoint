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
	"time"
)

// SiemResponse is the response from TAP SIEM API Endpoint.
type SiemResponse struct {
	QueryEndTime      string     `json:"queryEndTime,omitempty"`
	BlockedClicks     []*Click   `json:"clicksBlocked,omitempty"`
	PermittedClicks   []*Click   `json:"clicksPermitted,omitempty"`
	DeliveredMessages []*Message `json:"messagesDelivered,omitempty"`
	BlockedMessages   []*Message `json:"messagesBlocked,omitempty"`
}

// Message is a message with threats.
type Message struct {
	Category string `json:"category,omitempty"`
	// Blocked messages
	Blocked bool `json:"blocked,omitempty"`
	// Delivered messages
	Delivered bool `json:"delivered,omitempty"`
	// The unique id of the message.
	ID string `json:"id,omitempty"`
	// A list of email addresses contained within the CC: header, excluding friendly names.
	CarbonCopyHeaderAddresses []string `json:"ccAddresses,omitempty"`
	// The name of the PPS cluster which processed the message.
	ClusterName string `json:"cluster,omitempty"`
	// The rewrite status of the message. If value is 'true', all instances of URL
	// threats within the message were successfully rewritten. If the value is 'false',
	// at least one instance of the a threat URL was not rewritten. If the value is 'na',
	// the message did not contain any URL-based threats.
	CompletelyRewritten bool `json:"completelyRewritten,omitempty"`
	// The email address contained in the From: header, excluding friendly name.
	FromHeaderAddresses []string `json:"fromAddress,omitempty"`
	// The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique.
	GUID string `json:"GUID,omitempty"`
	// The full content of the From: header, including any friendly name.
	FromHeader string `json:"headerFrom,omitempty"`
	// If present, the full content of the Reply-To: header, including any friendly names.
	ReplyToHeader string `json:"headerReplyTo,omitempty"`
	// The impostor score of the message. Higher scores indicate higher certainty.
	ImpostorScore float64 `json:"impostorScore,omitempty"`
	// The malware score of the message. Higher scores indicate higher certainty.
	MalwareScore float64 `json:"malwareScore,omitempty"`
	// Message-ID extracted from the headers of the email message. It can be used to look
	// up the associated message in PPS and is not unique.
	MessageID string `json:"messageID,omitempty"`
	// A collection of MessagePart objects.
	MessageParts []*MessagePart `json:"messageParts,omitempty"`
	// The size in bytes of the message, including headers and attachments.
	MessageSize float64 `json:"messageSize,omitempty"`
	// When the message was delivered to the user or quarantined by PPS
	MessageTimestamp time.Time `json:"messageTime,omitempty"`
	// The list of PPS modules which processed the message.
	ModulesRun []string `json:"modulesRun,omitempty"`
	// The phish score of the message. Higher scores indicate higher certainty.
	PhishScore float64 `json:"phishScore,omitempty"`
	// The policy routes that the message matched during processing by PPS.
	PolicyRoutes []string `json:"policyRoutes,omitempty"`
	// The queue ID of the message within PPS. It can be used to identify
	// the message in PPS and is not unique.
	QID string `json:"QID,omitempty"`
	// The name of the folder which contains the quarantined message.
	// This appears only for messagesBlocked.
	QuarantineFolder string `json:"quarantineFolder,omitempty"`
	// The name of the rule which quarantined the message.
	// This appears only for messagesBlocked events.
	QuarantineRule string `json:"quarantineRule,omitempty"`
	// An array containing the email addresses of the SMTP (envelope) recipients
	RecipientEmailAddress []string `json:"recipient,omitempty"`
	// The email address contained in the Reply-To: header, excluding friendly name.
	ReplyToHeaderAddress []string `json:"replyToAddress,omitempty"`
	// The email address of the SMTP (envelope) sender. The user-part is hashed. The domain-part is cleartext.
	SenderEmailAddress string `json:"sender,omitempty"`
	// The IP address of the sender.
	SenderIPAddress string `json:"senderIP,omitempty"`
	// The spam score of the message. Higher scores indicate higher certainty.
	SpamScore float64 `json:"spamScore,omitempty"`
	// The subject line of the message, if available.
	Subject string `json:"subject,omitempty"`
	// An array of structures which contain details about detected threats within the message.
	// There may be more than one threat per message.
	Threats []*Threat `json:"threatsInfoMap,omitempty"`
	// A list of email addresses contained within the To: header, excluding friendly names.
	ToHeaderAddresses []string `json:"toAddresses,omitempty"`
	// The content of the X-Mailer: header, if present.
	XmailerHeader string `json:"xmailer,omitempty"`
}

// Threat contain details about detected threats within the message.
type Threat struct {
	// An identifier for the campaign of which the threat is a member, if available
	// at the time of the query. Threats can be linked to campaigns even after
	// these events are retrieved.
	CampaignID string `json:"campaignID,omitempty"`
	// The category of threat found in the message: Malware, Phish, Spam,
	// Impostor (for BEC/Message Text threats).
	Classification string `json:"classification,omitempty"`
	// The artifact which was condemned by Proofpoint. The malicious URL, hash of
	// the attachment threat, or email address of the impostor sender.
	Name string `json:"threat,omitempty"`
	// The unique identifier associated with this threat. It can be used to query
	// the forensics and campaign endpoints.
	ID string `json:"threatID,omitempty"`
	// The current state of the threat: active, falsepositive, cleared.
	ThreatStatus string `json:"threatStatus,omitempty"`
	// Proofpoint assigned the threatStatus at this time.
	Timestamp time.Time `json:"threatTime,omitempty"`
	// Whether the threat was an attachment, URL, or message type.
	Type string `json:"threatType,omitempty"`
	// A link to the entry about the threat on the TAP Dashboard
	URL string `json:"threatUrl,omitempty"`
}

// MessagePart is a part of the message related to the click to a malicious URL.
type MessagePart struct {
	// The true, detected Content-Type of the messagePart. This may differ from the oContentType value.
	ContentType string `json:"contentType,omitempty"`
	// If the value is "inline," the messagePart is a message body. If the value is
	// "attached," the messagePart is an attachment.
	Disposition string `json:"disposition,omitempty"`
	// The filename of the messagePart.
	FileName string `json:"filename,omitempty"`
	// The MD5 hash of the messagePart contents.
	MD5 string `json:"md5,omitempty"`
	// The declared Content-Type of the messagePart.
	DeclaredContentType string `json:"oContentType,omitempty"`
	// The verdict returned by the sandbox during the scanning process.
	// "unsupported": the messagePart is not supported by Attachment Defense
	// and was not scanned.
	// "clean": the sandbox returned a clean verdict.
	// "threat": the sandbox returned a malicious verdict.
	// "prefilter": the messagePart contained no active content, and was therefore
	// not sent to the sandboxing service.
	// "uploaded": the message was uploaded by PPS to the sandboxing service, but
	// did not yet have a verdict at the time the message was processed.
	// "inprogress": the attachment had been uploaded and was awaiting scanning
	// at the time the message was processed.
	// "uploaddisabled": the attachment was eligible for scanning, but was not
	// uploaded because of PPS policy.
	SandboxStatus string `json:"sandboxStatus,omitempty"`
	// The SHA256 hash of the messagePart contents.
	SHA256 string `json:"sha256,omitempty"`
}

// Click is a click to malicious URL.
type Click struct {
	Category string `json:"category,omitempty"`
	// Blocked clicks
	Blocked bool `json:"blocked,omitempty"`
	// Permitted clicks
	Permitted bool `json:"permitted,omitempty"`
	// The unique id of the click.
	ID string `json:"id,omitempty"`
	// The ID of the message within PPS. It can be used to identify the message in PPS and
	// is guaranteed to be unique.
	GUID string `json:"GUID,omitempty"`
	// An identifier for the campaign of which the threat is a member, if available
	// at the time of the query. Threats can be linked to campaigns even after these events are retrieved.
	CampaignID string `json:"campaignID,omitempty"`
	// The threat category of the malicious URL, e.g. Malware, Phish, Spam.
	Classification string `json:"classification,omitempty"`
	// The external IP address of the user who clicked on the link. If the user is behind a firewall
	// performing network address translation, the IP address of the firewall will be shown.
	ClickIPAddress string `json:"clickIP,omitempty"`
	// The time the user clicked on the URL.
	ClickTimestamp time.Time `json:"clickTime,omitempty"`
	// The email address of the recipient.
	RecipientEmailAddresses string `json:"recipient,omitempty"`
	// The email address of the sender. The user-part is hashed. The domain-part is cleartext.
	SenderEmailddress string `json:"sender,omitempty"`
	// The IP address of the sender.
	SenderIPAddress string `json:"senderIP,omitempty"`
	// The unique identifier associated with this threat. It can be used to query the forensics.
	// and campaign endpoints.
	ThreatID string `json:"threatID,omitempty"`
	// Proofpoint identified the URL as a threat at this time.
	ThreatTimestamp time.Time `json:"threatTime,omitempty"`
	// A link to the entry on the TAP Dashboard for the particular threat.
	ThreatURL string `json:"threatURL,omitempty"`
	// The current state of the threat, e.g. active, falsepositive, cleared.
	ThreatStatus string `json:"threatStatus,omitempty"`
	// The malicious URL which was clicked
	URL string `json:"url,omitempty"`
	// The User-Agent header from the clicker's HTTP request
	UserAgent string `json:"userAgent,omitempty"`
}

// GetSiemIssues fetches events for clicks to malicious URLs permitted and messages
// delivered containing a known attachment threat within the specified time period.
func (c *Client) GetSiemIssues(opts map[string]interface{}) ([]*Click, []*Message, error) {
	return []*Click{}, []*Message{}, nil
}

// GetSiemAll fetches events for all clicks and messages relating to known threats
// within the specified time period.
func (c *Client) GetSiemAll(opts map[string]interface{}) ([]*Click, []*Message, error) {
	clicks := []*Click{}
	messages := []*Message{}
	apiOpts := make(map[string]interface{})
	apiOpts["request_uri"] = "siem/all?format=json&sinceSeconds=3600"
	b, err := c.callAPI(apiOpts)
	if err != nil {
		return clicks, messages, err
	}
	apiResponse := &SiemResponse{}
	if err := json.Unmarshal(b, &apiResponse); err != nil {
		return clicks, messages, err
	}

	for _, item := range apiResponse.BlockedClicks {
		item.Category = "blocked_clicks"
		item.Blocked = true
		clicks = append(clicks, item)
	}
	for _, item := range apiResponse.PermittedClicks {
		item.Category = "permitted_clicks"
		item.Permitted = true
		clicks = append(clicks, item)
	}
	for _, item := range apiResponse.BlockedMessages {
		item.Category = "blocked_messages"
		item.Blocked = true
		messages = append(messages, item)
	}
	for _, item := range apiResponse.DeliveredMessages {
		item.Category = "delivered_messages"
		item.Delivered = true
		messages = append(messages, item)
	}
	return clicks, messages, nil
}

// GetSiemDeliveredMessages fetches events for messages delivered in the specified time
// period which contained a known threat.
func (c *Client) GetSiemDeliveredMessages(opts map[string]interface{}) ([]*Message, error) {
	return []*Message{}, nil
}

// GetSiemBlockedMessages fetches events for messages blocked in the specified time
// period which contained a known threat.
func (c *Client) GetSiemBlockedMessages(opts map[string]interface{}) ([]*Message, error) {
	return []*Message{}, nil
}

// GetSiemPermittedClicks fetches events for clicks to malicious URLs permitted
// in the specified time period.
func (c *Client) GetSiemPermittedClicks(opts map[string]interface{}) ([]*Click, error) {
	return []*Click{}, nil
}

// GetSiemBlockedClicks fetches events for clicks to malicious URLs blocked in the
// specified time period.
func (c *Client) GetSiemBlockedClicks(opts map[string]interface{}) ([]*Click, error) {
	return []*Click{}, nil
}
