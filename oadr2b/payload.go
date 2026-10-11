package oadr2b

// OpenADR 2.0b payload types, written from the element names and
// namespaces of the 2.0b schema (the schema files themselves are not
// included). Field order follows the schema's sequences so that documents
// we write validate; unknown elements are ignored when reading.

import "encoding/xml"

// XML namespaces of OpenADR 2.0b documents.
const (
	NSOadr  = "http://openadr.org/oadr-2.0b/2012/07"
	NSEi    = "http://docs.oasis-open.org/ns/energyinterop/201110"
	NSPyld  = "http://docs.oasis-open.org/ns/energyinterop/201110/payloads"
	NSXcal  = "urn:ietf:params:xml:ns:icalendar-2.0"
	NSStrm  = "urn:ietf:params:xml:ns:icalendar-2.0:stream"
	NSEmix  = "http://docs.oasis-open.org/ns/emix/2011/06"
	NSPower = "http://docs.oasis-open.org/ns/emix/2011/06/power"
	NSScale = "http://docs.oasis-open.org/ns/emix/2011/06/siscale"
	NSDs    = "http://www.w3.org/2000/09/xmldsig#"
	NSXsi   = "http://www.w3.org/2001/XMLSchema-instance"
)

// SchemaVersion is the ei:schemaVersion every message carries.
const SchemaVersion = "2.0b"

// prefixes are the conventional prefixes written for each namespace.
var prefixes = []struct{ prefix, ns string }{
	{"oadr", NSOadr}, {"ei", NSEi}, {"pyld", NSPyld}, {"xcal", NSXcal}, {"strm", NSStrm},
	{"emix", NSEmix}, {"power", NSPower}, {"scale", NSScale}, {"ds", NSDs}, {"xsi", NSXsi},
}

// Payload is oadrPayload, the envelope of every message.
type Payload struct {
	XMLName      xml.Name     `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrPayload"`
	SignedObject SignedObject `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrSignedObject"`
}

// SignedObject holds exactly one message.
type SignedObject struct {
	// ID is the element's Id, read with or without the OpenADR
	// namespace and written by Marshal as oadr:Id.
	ID string `xml:"Id,attr,omitempty"`

	QueryRegistration         *QueryRegistration         `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrQueryRegistration"`
	CreatePartyRegistration   *CreatePartyRegistration   `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCreatePartyRegistration"`
	CreatedPartyRegistration  *CreatedPartyRegistration  `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCreatedPartyRegistration"`
	CancelPartyRegistration   *CancelPartyRegistration   `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCancelPartyRegistration"`
	CanceledPartyRegistration *CanceledPartyRegistration `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCanceledPartyRegistration"`
	RequestReregistration     *RequestReregistration     `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrRequestReregistration"`
	Response                  *Response                  `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrResponse"`
	Poll                      *Poll                      `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrPoll"`
	RequestEvent              *RequestEvent              `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrRequestEvent"`
	DistributeEvent           *DistributeEvent           `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrDistributeEvent"`
	CreatedEvent              *CreatedEvent              `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCreatedEvent"`
	RegisterReport            *RegisterReport            `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrRegisterReport"`
	RegisteredReport          *RegisteredReport          `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrRegisteredReport"`
	CreateReport              *CreateReport              `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCreateReport"`
	CreatedReport             *CreatedReport             `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCreatedReport"`
	UpdateReport              *UpdateReport              `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrUpdateReport"`
	UpdatedReport             *UpdatedReport             `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrUpdatedReport"`
	CancelReport              *CancelReport              `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCancelReport"`
	CanceledReport            *CanceledReport            `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCanceledReport"`
	CreateOpt                 *CreateOpt                 `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCreateOpt"`
	CreatedOpt                *CreatedOpt                `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCreatedOpt"`
	CancelOpt                 *CancelOpt                 `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCancelOpt"`
	CanceledOpt               *CanceledOpt               `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCanceledOpt"`
}

// ---- common parts -----------------------------------------------------------

// EiResponse is ei:eiResponse.
type EiResponse struct {
	ResponseCode        string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 responseCode"`
	ResponseDescription string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 responseDescription,omitempty"`
	RequestID           string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
}

// DurationProp is an element whose child is xcal:duration.
type DurationProp struct {
	Duration string `xml:"urn:ietf:params:xml:ns:icalendar-2.0 duration"`
}

// DtStart is xcal:dtstart.
type DtStart struct {
	DateTime string `xml:"urn:ietf:params:xml:ns:icalendar-2.0 date-time"`
}

// UID is xcal:uid.
type UID struct {
	Text string `xml:"urn:ietf:params:xml:ns:icalendar-2.0 text"`
}

// PayloadFloat is ei:payloadFloat.
type PayloadFloat struct {
	Value float64 `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 value"`
}

// QualifiedEventID is ei:qualifiedEventID.
type QualifiedEventID struct {
	EventID            string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eventID"`
	ModificationNumber uint32 `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 modificationNumber"`
}

// Target is ei:eiTarget (and other elements of the same type:
// reportSubject, reportDataSource, oadrDeviceClass). Members follow the
// schema's order; the grid-location members (pnodes, service areas and the
// like) are not modelled and are ignored when read.
type Target struct {
	EndDeviceAsset []EndDeviceAsset `xml:"http://docs.oasis-open.org/ns/emix/2011/06/power endDeviceAsset"`
	GroupID        []string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 groupID"`
	GroupName      []string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 groupName"`
	ResourceID     []string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 resourceID"`
	VenID          []string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID"`
	PartyID        []string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 partyID"`
}

// EndDeviceAsset is power:endDeviceAsset (a device class by mrid).
type EndDeviceAsset struct {
	MRID string `xml:"http://docs.oasis-open.org/ns/emix/2011/06/power mrid"`
}

// Empty is true when the target names nothing.
func (t *Target) Empty() bool {
	return t == nil || len(t.EndDeviceAsset)+len(t.GroupID)+len(t.GroupName)+len(t.ResourceID)+len(t.VenID)+len(t.PartyID) == 0
}

// Properties is xcal:properties of an active period, report interval or
// availability.
type Properties struct {
	DtStart      DtStart       `xml:"urn:ietf:params:xml:ns:icalendar-2.0 dtstart"`
	Duration     DurationProp  `xml:"urn:ietf:params:xml:ns:icalendar-2.0 duration"`
	Tolerance    *Tolerance    `xml:"urn:ietf:params:xml:ns:icalendar-2.0 tolerance"`
	Notification *DurationProp `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 x-eiNotification"`
	RampUp       *DurationProp `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 x-eiRampUp"`
	Recovery     *DurationProp `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 x-eiRecovery"`
}

// Tolerance is xcal:tolerance: tolerate/startafter is the start
// randomisation window of an event.
type Tolerance struct {
	Tolerate Tolerate `xml:"urn:ietf:params:xml:ns:icalendar-2.0 tolerate"`
}

// Tolerate is xcal:tolerate.
type Tolerate struct {
	StartAfter string `xml:"urn:ietf:params:xml:ns:icalendar-2.0 startafter,omitempty"`
}

// Components is the empty xcal:components of an active period.
type Components struct {
	Nil string `xml:"http://www.w3.org/2001/XMLSchema-instance nil,attr,omitempty"`
}

// Intervals is strm:intervals.
type Intervals struct {
	Interval []Interval `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 interval"`
}

// Interval is ei:interval: an event signal interval or a report interval.
type Interval struct {
	DtStart       *DtStart        `xml:"urn:ietf:params:xml:ns:icalendar-2.0 dtstart"`
	Duration      *DurationProp   `xml:"urn:ietf:params:xml:ns:icalendar-2.0 duration"`
	UID           *UID            `xml:"urn:ietf:params:xml:ns:icalendar-2.0 uid"`
	SignalPayload *SignalPayload  `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 signalPayload"`
	ReportPayload []ReportPayload `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrReportPayload"`
}

// SignalPayload is ei:signalPayload.
type SignalPayload struct {
	PayloadFloat PayloadFloat `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 payloadFloat"`
}

// ---- EiRegisterParty --------------------------------------------------------

// QueryRegistration asks the VTN what it supports.
type QueryRegistration struct {
	SchemaVersion string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	RequestID     string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
}

// CreatedPartyRegistration answers a query or a registration.
type CreatedPartyRegistration struct {
	SchemaVersion  string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse     EiResponse    `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	RegistrationID string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 registrationID,omitempty"`
	VenID          string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
	VtnID          string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 vtnID"`
	Profiles       Profiles      `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrProfiles"`
	PollFreq       *DurationProp `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrRequestedOadrPollFreq"`
}

// Profiles is oadr:oadrProfiles.
type Profiles struct {
	Profile []Profile `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrProfile"`
}

// Profile is one supported profile and its transports.
type Profile struct {
	Name       string     `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrProfileName"`
	Transports Transports `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrTransports"`
}

// Transports is oadr:oadrTransports.
type Transports struct {
	Transport []Transport `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrTransport"`
}

// Transport is oadr:oadrTransport.
type Transport struct {
	Name string `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrTransportName"`
}

// CreatePartyRegistration registers a VEN.
type CreatePartyRegistration struct {
	SchemaVersion    string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	RequestID        string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	RegistrationID   string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 registrationID,omitempty"`
	VenID            string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
	ProfileName      string `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrProfileName"`
	TransportName    string `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrTransportName"`
	TransportAddress string `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrTransportAddress,omitempty"`
	ReportOnly       bool   `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrReportOnly"`
	XMLSignature     bool   `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrXmlSignature"`
	VenName          string `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrVenName,omitempty"`
	HTTPPullModel    *bool  `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrHttpPullModel"`
}

// CancelPartyRegistration ends a registration (either party may send it).
type CancelPartyRegistration struct {
	SchemaVersion  string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	RequestID      string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	RegistrationID string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 registrationID"`
	VenID          string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// CanceledPartyRegistration answers a cancellation.
type CanceledPartyRegistration struct {
	SchemaVersion  string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse     EiResponse `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	RegistrationID string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 registrationID,omitempty"`
	VenID          string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// RequestReregistration asks the VEN to register again.
type RequestReregistration struct {
	SchemaVersion string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	VenID         string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID"`
}

// Response is the generic oadrResponse.
type Response struct {
	SchemaVersion string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse    EiResponse `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	VenID         string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// Poll asks the VTN for the next message (pull model).
type Poll struct {
	SchemaVersion string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	VenID         string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID"`
}

// ---- EiEvent ----------------------------------------------------------------

// RequestEvent asks for the VEN's events.
type RequestEvent struct {
	SchemaVersion  string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiRequestEvent EiRequestEvent `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads eiRequestEvent"`
}

// EiRequestEvent is pyld:eiRequestEvent.
type EiRequestEvent struct {
	RequestID  string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	VenID      string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID"`
	ReplyLimit uint32 `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads replyLimit,omitempty"`
}

// DistributeEvent carries every current event for the VEN.
type DistributeEvent struct {
	SchemaVersion string      `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse    *EiResponse `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	RequestID     string      `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	VtnID         string      `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 vtnID"`
	Events        []OadrEvent `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrEvent"`
}

// OadrEvent is one event and whether the VEN must answer it.
type OadrEvent struct {
	EiEvent          EiEvent `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiEvent"`
	ResponseRequired string  `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrResponseRequired"`
}

// EiEvent is ei:eiEvent.
type EiEvent struct {
	Descriptor   EventDescriptor `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eventDescriptor"`
	ActivePeriod ActivePeriod    `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiActivePeriod"`
	Signals      EventSignals    `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiEventSignals"`
	Target       Target          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiTarget"`
}

// EventDescriptor is ei:eventDescriptor.
type EventDescriptor struct {
	EventID              string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eventID"`
	ModificationNumber   uint32        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 modificationNumber"`
	ModificationDateTime string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 modificationDateTime,omitempty"`
	ModificationReason   string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 modificationReason,omitempty"`
	Priority             *uint32       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 priority"`
	MarketContext        MarketContext `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiMarketContext"`
	CreatedDateTime      string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 createdDateTime"`
	EventStatus          string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eventStatus"`
	TestEvent            string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 testEvent,omitempty"`
	VtnComment           string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 vtnComment,omitempty"`
}

// MarketContext is ei:eiMarketContext.
type MarketContext struct {
	MarketContext string `xml:"http://docs.oasis-open.org/ns/emix/2011/06 marketContext"`
}

// ActivePeriod is ei:eiActivePeriod.
type ActivePeriod struct {
	Properties Properties `xml:"urn:ietf:params:xml:ns:icalendar-2.0 properties"`
	Components Components `xml:"urn:ietf:params:xml:ns:icalendar-2.0 components"`
}

// EventSignals is ei:eiEventSignals.
type EventSignals struct {
	Signal   []EventSignal  `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiEventSignal"`
	Baseline *EventBaseline `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiEventBaseline"`
}

// EventSignal is one signal of an event. Its eiTarget holds only
// endDeviceAsset device classes (rule 111); itemBase gives the units of
// the well-known signals (Table 1, rule 104).
type EventSignal struct {
	Intervals    Intervals     `xml:"urn:ietf:params:xml:ns:icalendar-2.0:stream intervals"`
	Target       *Target       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiTarget"`
	SignalName   string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 signalName"`
	SignalType   string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 signalType"`
	SignalID     string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 signalID"`
	ItemBase     *ItemBase     `xml:",any"`
	CurrentValue *CurrentValue `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 currentValue"`
}

// EventBaseline is ei:eiEventBaseline (2.0b only).
type EventBaseline struct {
	DtStart      DtStart      `xml:"urn:ietf:params:xml:ns:icalendar-2.0 dtstart"`
	Duration     DurationProp `xml:"urn:ietf:params:xml:ns:icalendar-2.0 duration"`
	Intervals    Intervals    `xml:"urn:ietf:params:xml:ns:icalendar-2.0:stream intervals"`
	BaselineID   string       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 baselineID"`
	ResourceID   []string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 resourceID"`
	BaselineName string       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 baselineName"`
	ItemBase     *ItemBase    `xml:",any"`
}

// CurrentValue is ei:currentValue.
type CurrentValue struct {
	PayloadFloat PayloadFloat `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 payloadFloat"`
}

// CreatedEvent is the VEN's opt-in or opt-out of events.
type CreatedEvent struct {
	SchemaVersion  string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiCreatedEvent EiCreatedEvent `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads eiCreatedEvent"`
}

// EiCreatedEvent is pyld:eiCreatedEvent (in the payloads namespace, like
// pyld:eiRequestEvent).
type EiCreatedEvent struct {
	EiResponse     EiResponse      `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	EventResponses *EventResponses `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eventResponses"`
	VenID          string          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID"`
}

// EventResponses is ei:eventResponses.
type EventResponses struct {
	Response []EventResponse `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eventResponse"`
}

// EventResponse is the answer to one event.
type EventResponse struct {
	ResponseCode        string           `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 responseCode"`
	ResponseDescription string           `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 responseDescription,omitempty"`
	RequestID           string           `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	QualifiedEventID    QualifiedEventID `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 qualifiedEventID"`
	OptType             string           `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 optType"`
}

// ---- EiReport ---------------------------------------------------------------

// RegisterReport announces the reports a party can send.
type RegisterReport struct {
	SchemaVersion   string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	RequestID       string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	Reports         []Report `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrReport"`
	VenID           string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
	ReportRequestID string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportRequestID,omitempty"`
}

// Report is oadr:oadrReport: metadata (descriptions) or data (intervals).
type Report struct {
	DtStart           *DtStart            `xml:"urn:ietf:params:xml:ns:icalendar-2.0 dtstart"`
	Duration          *DurationProp       `xml:"urn:ietf:params:xml:ns:icalendar-2.0 duration"`
	Intervals         *Intervals          `xml:"urn:ietf:params:xml:ns:icalendar-2.0:stream intervals"`
	EiReportID        string              `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiReportID,omitempty"`
	Descriptions      []ReportDescription `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrReportDescription"`
	ReportRequestID   string              `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportRequestID"`
	ReportSpecifierID string              `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportSpecifierID"`
	ReportName        string              `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportName,omitempty"`
	CreatedDateTime   string              `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 createdDateTime"`
}

// ReportDescription describes one data point (rID) of a report.
type ReportDescription struct {
	RID              string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 rID"`
	ReportSubject    *Target       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportSubject"`
	ReportDataSource *Target       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportDataSource"`
	ReportType       string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportType"`
	ItemBase         *ItemBase     `xml:",any"`
	ReadingType      string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 readingType"`
	MarketContext    string        `xml:"http://docs.oasis-open.org/ns/emix/2011/06 marketContext,omitempty"`
	SamplingRate     *SamplingRate `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrSamplingRate"`
}

// SamplingRate is oadr:oadrSamplingRate.
type SamplingRate struct {
	MinPeriod string `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrMinPeriod"`
	MaxPeriod string `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrMaxPeriod"`
	OnChange  bool   `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrOnChange"`
}

// ReportPayload is one rID's value in a report interval.
type ReportPayload struct {
	RID            string          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 rID"`
	Confidence     *uint32         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 confidence"`
	Accuracy       *float64        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 accuracy"`
	PayloadFloat   *PayloadFloat   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 payloadFloat"`
	ResourceStatus *ResourceStatus `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrPayloadResourceStatus"`
	DataQuality    string          `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrDataQuality,omitempty"`
}

// ResourceStatus is oadr:oadrPayloadResourceStatus.
type ResourceStatus struct {
	Online           bool              `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrOnline"`
	ManualOverride   bool              `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrManualOverride"`
	LoadControlState *LoadControlState `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrLoadControlState"`
}

// LoadControlState is oadr:oadrLoadControlState.
type LoadControlState struct {
	Capacity      *LoadControlValue `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCapacity"`
	LevelOffset   *LoadControlValue `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrLevelOffset"`
	PercentOffset *LoadControlValue `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrPercentOffset"`
	SetPoint      *LoadControlValue `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrSetPoint"`
}

// LoadControlValue is one load control quantity.
type LoadControlValue struct {
	Min     *float64 `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrMin"`
	Max     *float64 `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrMax"`
	Current float64  `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCurrent"`
	Normal  *float64 `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrNormal"`
}

// RegisteredReport answers a RegisterReport, optionally subscribing.
type RegisteredReport struct {
	SchemaVersion  string          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse     EiResponse      `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	ReportRequests []ReportRequest `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrReportRequest"`
	VenID          string          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// ReportRequest subscribes to a report.
type ReportRequest struct {
	ReportRequestID string          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportRequestID"`
	ReportSpecifier ReportSpecifier `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportSpecifier"`
}

// ReportSpecifier is ei:reportSpecifier.
type ReportSpecifier struct {
	ReportSpecifierID  string             `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportSpecifierID"`
	Granularity        DurationProp       `xml:"urn:ietf:params:xml:ns:icalendar-2.0 granularity"`
	ReportBackDuration DurationProp       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportBackDuration"`
	ReportInterval     *ReportInterval    `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportInterval"`
	SpecifierPayloads  []SpecifierPayload `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 specifierPayload"`
}

// ReportInterval is ei:reportInterval.
type ReportInterval struct {
	Properties Properties `xml:"urn:ietf:params:xml:ns:icalendar-2.0 properties"`
}

// SpecifierPayload names one rID of a report request.
type SpecifierPayload struct {
	RID         string    `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 rID"`
	ItemBase    *ItemBase `xml:",any"`
	ReadingType string    `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 readingType"`
}

// CreateReport requests reports.
type CreateReport struct {
	SchemaVersion  string          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	RequestID      string          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	ReportRequests []ReportRequest `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrReportRequest"`
	VenID          string          `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// CreatedReport acknowledges report requests.
type CreatedReport struct {
	SchemaVersion  string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse     EiResponse     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	PendingReports PendingReports `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrPendingReports"`
	VenID          string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// PendingReports is oadr:oadrPendingReports.
type PendingReports struct {
	ReportRequestID []string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportRequestID"`
}

// UpdateReport carries report data.
type UpdateReport struct {
	SchemaVersion string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	RequestID     string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	Reports       []Report `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrReport"`
	VenID         string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// UpdatedReport acknowledges report data.
type UpdatedReport struct {
	SchemaVersion string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse    EiResponse    `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	CancelReport  *CancelReport `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrCancelReport"`
	VenID         string        `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// CancelReport cancels report requests.
type CancelReport struct {
	SchemaVersion   string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	RequestID       string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	ReportRequestID []string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 reportRequestID"`
	ReportToFollow  bool     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads reportToFollow"`
	VenID           string   `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// CanceledReport acknowledges a cancellation.
type CanceledReport struct {
	SchemaVersion  string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse     EiResponse     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	PendingReports PendingReports `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrPendingReports"`
	VenID          string         `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID,omitempty"`
}

// ---- EiOpt ------------------------------------------------------------------

// CreateOpt is a VEN's opt schedule or opt-in/out of an event. The
// schema's sequence: the EiOpt part (optID … createdDateTime) and then
// requestID, qualifiedEventID, eiTarget (required) and oadrDeviceClass.
type CreateOpt struct {
	SchemaVersion    string            `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	OptID            string            `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 optID"`
	OptType          string            `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 optType"`
	OptReason        string            `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 optReason"`
	MarketContext    string            `xml:"http://docs.oasis-open.org/ns/emix/2011/06 marketContext,omitempty"`
	VenID            string            `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID"`
	Vavailability    *Vavailability    `xml:"urn:ietf:params:xml:ns:icalendar-2.0 vavailability"`
	CreatedDateTime  string            `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 createdDateTime"`
	RequestID        string            `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	QualifiedEventID *QualifiedEventID `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 qualifiedEventID"`
	Target           Target            `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiTarget"`
	DeviceClass      *Target           `xml:"http://openadr.org/oadr-2.0b/2012/07 oadrDeviceClass"`
}

// Vavailability is xcal:vavailability: the periods of an opt schedule.
type Vavailability struct {
	Components AvailableComponents `xml:"urn:ietf:params:xml:ns:icalendar-2.0 components"`
}

// AvailableComponents holds the xcal:available periods.
type AvailableComponents struct {
	Available []Available `xml:"urn:ietf:params:xml:ns:icalendar-2.0 available"`
}

// Available is one xcal:available period.
type Available struct {
	Properties Properties `xml:"urn:ietf:params:xml:ns:icalendar-2.0 properties"`
}

// CreatedOpt acknowledges an opt.
type CreatedOpt struct {
	SchemaVersion string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse    EiResponse `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	OptID         string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 optID"`
}

// CancelOpt withdraws an opt.
type CancelOpt struct {
	SchemaVersion string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	RequestID     string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	OptID         string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 optID"`
	VenID         string `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 venID"`
}

// CanceledOpt acknowledges an opt cancellation.
type CanceledOpt struct {
	SchemaVersion string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 schemaVersion,attr,omitempty"`
	EiResponse    EiResponse `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	OptID         string     `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 optID"`
}
