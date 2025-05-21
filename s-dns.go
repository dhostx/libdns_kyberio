package sdns

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"github.com/libdns/libdns"
	"io"
	"net/http"
	"strings"
	"time"
)

const url = "https://robot.s-dns.de:8488/"

type GetRootZoneRequest struct {
	XMLName  xml.Name `xml:"zoneRequest"`
	Action   string   `xml:"action,attr"`
	DDNSKey  string   `xml:"ddnskey,attr"`
	Hostname string   `xml:"hostname"`
}

type GetRootZoneResponse struct {
	XMLName  xml.Name `xml:"zoneRequest"`
	Status   string   `xml:"status,attr"`
	Zonename string   `xml:"zonename"`
	Hostname string   `xml:"hostname"`
}

type ZoneRequest struct {
	XMLName xml.Name `xml:"zoneRequest"`
	Zone    Zone     `xml:"zone"`
}

// Zone represents the <zone> element
type Zone struct {
	Name     string           `xml:"name,attr"`               // Zone name attribute
	Action   string           `xml:"action,attr,omitempty"`   // Zone action attribute
	DDNSKey  string           `xml:"ddnskey,attr,omitempty"`  // Zone key attribute
	Reseller string           `xml:"reseller,attr,omitempty"` // Resellername (zoneexport)
	DNSSec   bool             `xml:"dnssec,attr,omitempty"`   // is dnssec active (zoneexport)
	SOA      SOA              `xml:"soa"`                     // SOA values (export)
	Records  []ResourceRecord `xml:"rr"`                      // Slice of resource records

}

// ResourceRecord represents an <rr> element within <zone>
type ResourceRecord struct {
	Host            string `xml:"host,attr"`                      // Host attribute
	Type            string `xml:"type,attr"`                      // Type attribute (e.g., A, TXT)
	Value           string `xml:"value,attr"`                     // Value attribute (e.g., IP address or TXT value)
	KeepExisting    bool   `xml:"keepExisting,attr,omitempty"`    // Keep existing records flag
	PerformedAction string `xml:"performedAction,attr,omitempty"` // Optional: Response action (e.g., "updated")
}

// Struct for XML Response
type ZoneResponse struct {
	XMLName xml.Name         `xml:"zoneRequest"`
	Status  string           `xml:"status,attr"`
	Zone    string           `xml:"zone,attr"`
	Action  string           `xml:"action,attr"`
	Records []ResourceRecord `xml:"rr"`
}

// SOA represents the `<soa>` element in the XML.
type SOA struct {
	Refresh int `xml:"refresh,attr"`
	Retry   int `xml:"retry,attr"`
	Expire  int `xml:"expire,attr"`
	MTTL    int `xml:"mttl,attr"`
}

// doRequest sends an HTTP request and returns the response body as bytes or an error.
// It ensures the response body is closed after reading and checks for non-OK status codes.
func doRequest(request *http.Request) ([]byte, error) {
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return body, nil

}

type ZoneExport struct {
	records []ResourceRecord
	ttl     int
}

// getZone retrieves and parses zone information using the provided context, DDNS key, and zone name.
// It returns the ZoneExport containing records and TTL, or an error if the operation fails.
func getZone(ctx context.Context, ddnsKey string, zoneName string) (export ZoneExport, e error) {
	// Prepare XML
	requestData := ZoneRequest{
		Zone: Zone{
			Name:    zoneName,
			Action:  "GETZONE",
			DDNSKey: ddnsKey,
		},
	}
	xmlData, err := xml.MarshalIndent(requestData, "", "  ")
	if err != nil {
		return ZoneExport{}, fmt.Errorf("error marshaling XML: %v", err)
	}

	// Submit the request
	request, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(xmlData))
	if err != nil {
		return ZoneExport{}, fmt.Errorf("error making POST request: %v", err)
	}

	body, err := doRequest(request)
	if err != nil {
		return ZoneExport{}, err
	}

	var response Zone
	err = xml.Unmarshal(body, &response)
	if err != nil {
		return ZoneExport{}, fmt.Errorf("error unmarshaling XML response: %v", err)
	}

	retvalue := ZoneExport{
		records: response.Records,
		ttl:     response.SOA.MTTL,
	}
	return retvalue, nil
}

// GetRootZone retrieves the root DNS zone name associated with the given hostname using the specified DDNS key.
// It performs an XML-based HTTP POST request to an external service and parses the response to obtain the zone name.
// Returns the zone name if found, or an error if the operation fails or the zone is not found.
func GetRootZone(ddnsKey string, hostname string) (zonename string, err error) {
	// Create the zoneRequest
	requestData := GetRootZoneRequest{
		Action:   "getRootZone",
		DDNSKey:  ddnsKey,
		Hostname: hostname,
	}

	// Marshal the request into XML
	xmlData, err := xml.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("error marshaling XML: %v", err)
	}

	// Make the POST request
	resp, err := http.Post(url, "application/xml", bytes.NewReader(xmlData))
	if err != nil {
		return "", fmt.Errorf("error making POST request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	// Unmarshal the response XML
	var response GetRootZoneResponse
	err = xml.Unmarshal(body, &response)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling XML response: %v", err)
	}

	// Check if the zone was found
	if response.Status != "found" {
		return "", fmt.Errorf("zone not found for hostname %s", hostname)
	}

	return response.Zonename, nil
}

// AddOrUpdateRR sends a request to add or update DNS resource records in a specified zone based on provided inputs.
// Parameters: ctx (execution context), ddnsKey (authentication key), zoneName (DNS zone name), records (records to update),
// keepExisting (flag to retain or overwrite existing records).
// Returns: A slice of updated or added resource records and an error if the operation fails.
func AddOrUpdateRR(ctx context.Context, ddnsKey string, zoneName string, records []libdns.Record, keepExisting bool) ([]ResourceRecord, error) {
	// Create the request object
	var recordsToAppend []ResourceRecord

	for _, record := range records {
		var rec = record.RR()
		recordsToAppend = append(recordsToAppend, ResourceRecord{
			Host:         rec.Name,
			Type:         rec.Type,
			Value:        rec.Data,
			KeepExisting: keepExisting,
		})

	}

	request := ZoneRequest{
		Zone: Zone{
			Name:    zoneName,
			Action:  "ADDORUPDATERR", // Action based on your request
			DDNSKey: ddnsKey,
			Records: recordsToAppend,
		},
	}

	// Marshal the request object to XML
	xmlData, err := xml.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}

	// Add the XML header
	xmlHeader := []byte(`<?xml version="1.0" encoding="ISO-8859-1"?>` + "\n")
	finalXML := append(xmlHeader, xmlData...)

	// Create a new HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(finalXML))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")

	respBody, err := doRequest(req)
	if err != nil {
		return nil, err
	}

	var response ZoneResponse
	err = xml.Unmarshal(respBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if strings.EqualFold(response.Status, "ok") {
		return response.Records, nil
	}

	return nil, fmt.Errorf("failed to add or update records: %s", response.Status)
}

// DeleteRR deletes specified resource records from a DNS zone using the provided ddnsKey and zoneName.
// It sends a POST request with the required XML payload and returns the deleted resource records or an error.
func DeleteRR(ctx context.Context, ddnsKey string, zoneName string, records []libdns.Record) (deletedRRs []ResourceRecord, err error) {
	recordsToDelete := []ResourceRecord{}
	for _, record := range records {
		var rec = record.RR()
		recordsToDelete = append(recordsToDelete,
			ResourceRecord{
				Host:  rec.Name,
				Type:  rec.Type,
				Value: rec.Data,
			})
	}
	request := ZoneRequest{
		Zone: Zone{
			Name:    zoneName,
			Action:  "DELRR",
			Records: recordsToDelete,
			DDNSKey: ddnsKey,
		},
	}

	xmlData, err := xml.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}

	xmlHeader := []byte(`<?xml version="1.0" encoding="ISO-8859-1"?>` + "\n")
	finalXML := append(xmlHeader, xmlData...)

	resp, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(finalXML))
	if err != nil {
		return nil, fmt.Errorf("error making POST request: %v", err)
	}

	respBody, err := doRequest(resp)
	if err != nil {
		return nil, err
	}

	var response ZoneResponse
	err = xml.Unmarshal(respBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	return response.Records, nil
}

// appendRecords appends new DNS records to a specified zone without modifying existing records.
// It retrieves the zone TTL from the SOA record and returns only the newly added records.
// Parameters: ctx (context), ddnsKey (authentication key), zoneName (zone name), records (DNS records to append).
// Returns: A slice of newly added DNS records and an error if any occurs during the operation.
func appendRecords(ctx context.Context, ddnsKey string, zoneName string, records []libdns.Record) (appendedRecords []libdns.Record, err error) {

	// fetch all records to get the SOA -> ttl
	zoneExport, err := getZone(ctx, ddnsKey, zoneName)
	if err != nil {
		return nil, err
	}

	// perform the update, existing records will not be updated
	resultRecords, err := AddOrUpdateRR(ctx, ddnsKey, zoneName, records, true)
	if err != nil {
		return nil, err
	}

	// return only newly added records
	for _, record := range resultRecords {
		if record.PerformedAction == "added" {
			appendedRecords = append(appendedRecords, libdns.RR{
				Type: record.Type,
				Name: record.Host,
				Data: record.Value,
				TTL:  time.Duration(zoneExport.ttl) * time.Second,
			})
		}
	}

	return appendedRecords, nil
}

// setRecords updates or adds DNS records in the specified zone and returns only the records that were updated.
// It fetches the current zone data to determine TTL and updates or adds records using the provided data.
// ctx is the execution context, ddnsKey is the key for authentication, zoneName specifies the DNS zone,
// and records is the slice of libdns.Record containing the records to update.
// Returns a slice of updated libdns.Record and an error if the operation fails.
func setRecords(ctx context.Context, ddnsKey string, zoneName string, records []libdns.Record) (updatedRecords []libdns.Record, err error) {
	// fetch all records to get the SOA -> ttl
	zoneExport, err := getZone(ctx, ddnsKey, zoneName)
	if err != nil {
		return nil, err
	}

	// perform the update, existing records will be updated
	resultRecords, err := AddOrUpdateRR(ctx, ddnsKey, zoneName, records, false)
	if err != nil {
		return nil, err
	}

	// return only newly added records
	for _, record := range resultRecords {
		if record.PerformedAction == "updated" {
			updatedRecords = append(updatedRecords, libdns.RR{
				Type: record.Type,
				Name: record.Host,
				Data: record.Value,
				TTL:  time.Duration(zoneExport.ttl) * time.Second,
			})
		}
	}

	return updatedRecords, nil
}

// getRecords retrieves DNS records for a specific zone using the provided DDNS key and zone name.
// It returns a slice of libdns.Record and an error.
// The function fetches and parses zone data via getZone, then maps it to the libdns.Record structure.
func getRecords(ctx context.Context, ddnsKey string, zoneName string) (records []libdns.Record, err error) {
	zoneExport, err := getZone(ctx, ddnsKey, zoneName)
	if err != nil {
		return nil, err
	}

	for _, record := range zoneExport.records {
		records = append(records, libdns.RR{
			Name: record.Host,
			Type: record.Type,
			Data: record.Value,
			TTL:  time.Duration(zoneExport.ttl) * time.Second,
		})
	}
	return records, nil
}

// deleteRecords removes DNS records from the specified zone and returns the deleted records or an error if the operation fails.
func deleteRecords(ctx context.Context, ddnsKey string, zoneName string, records []libdns.Record) (recordsDeleted []libdns.Record, err error) {
	deletedRecords, err := DeleteRR(ctx, ddnsKey, zoneName, records)
	if err != nil {
		return nil, err
	}
	zoneExport, err := getZone(ctx, ddnsKey, zoneName)
	if err != nil {
		return nil, err
	}

	for _, record := range deletedRecords {
		if record.PerformedAction == "deleted" {
			recordsDeleted = append(recordsDeleted, libdns.RR{
				Name: record.Host,
				Type: record.Type,
				Data: record.Value,
				TTL:  time.Duration(zoneExport.ttl) * time.Second,
			})
		}
	}

	return recordsDeleted, nil
}
