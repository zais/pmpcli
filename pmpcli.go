package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
)

// -----------------------------------------------------------------------------
// Version
// -----------------------------------------------------------------------------

// BUILD number

// VERSION of this piece of ***
const VERSION = "0.2.0." + BUILD

// VERSIONAPI engine/plugin versions
const VERSIONAPI = "engine: 8.5.0.8502 / plugin: 1.0.2.4"

// -----------------------------------------------------------------------------
// Log level
// -----------------------------------------------------------------------------

// DEBUG is debug
var DEBUG = false

// VERBOSE output
var VERBOSE = false

// Info prints if verbose
func Info(v ...interface{}) {
	if VERBOSE {
		log.Println(v...)
	}
}

// Infof prints if verbose
func Infof(format string, v ...interface{}) {
	if VERBOSE {
		log.Printf(format, v...)
	}
}

// Debug prints if debug
func Debug(v ...interface{}) {
	if DEBUG {
		log.Println(v...)
	}
}

// Debugf prints if debug
func Debugf(format string, v ...interface{}) {
	if DEBUG {
		log.Printf(format, v...)
	}
}

// -----------------------------------------------------------------------------
// PMP Client
// -----------------------------------------------------------------------------

// PMPMode defines client behavior
type PMPMode int

const (
	// PMPModePlugin emulate plugin
	PMPModePlugin PMPMode = 1 + iota
	// PMPModeBrowser emulate browser
	PMPModeBrowser
)

// PMPAPIResult is basic json resopnse
type PMPAPIResult struct {
	Operation struct {
		// name/status
		Name   string `json:"name"`
		Result struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"result"`
		Details struct {
			// GET_AUTHENTICATION_MODE
			BuildNumber           string `json:"BUILDNUMBER,omitempty"`
			DefaultDomain         string `json:"DEFAULTDOMAIN,omitempty"`
			FirsFactor            string `json:"FIRSFACTOR,omitempty"`
			IsSecondFactorEnabled string `json:"ISSECONDFACTORENABLED,omitempty"`
			SecondFactor          string `json:"SecondFactor,omitempty"`
			MSPEnabled            string `json:"MSPENABLED,omitempty"`
			SessionTimeout        string `json:"SESSIONTIMEOUT,omitempty"`
			DomainList            []struct {
				DomainName string `json:"DOMAINNAME"`
			} `json:"DOMAINLIST,omitempty"`
			// auth
			AuthKey     string `json:"AUTHKEY,omitempty"`
			Permissions struct {
				UserDetails struct {
					OrgList map[string]struct {
						OrgID      int    `json:"ORGID"`
						OrgName    string `json:"ORGNAME"`
						OrgURLName string `json:"ORGURLNAME"`
					} `json:"ORGLIST"`
					UserEmailID  string `json:"USEREMAILID"`
					UserFullName string `json:"USERFULLNAME"`
				} `json:"USERDETAILS,omitempty"`
			} `json:"PERMISSIONS,omitempty"`
			// GET_RESOURCEACCOUNTLIST
			AccountList []struct {
				AccountID               string   `json:"ACCOUNT ID"`
				AccountName             string   `json:"ACCOUNT NAME"`
				AutoLogonList           []string `json:"AUTOLOGONLIST"`
				AutoLogonStatus         string   `json:"AUTOLOGONSTATUS"`
				IsReasonRequired        string   `json:"ISREASONREQUIRED"`
				IsTicketIDReqd          string   `json:"IS_TICKETID_REQD"`
				IsTicketIDReqdAcw       string   `json:"IS_TICKETID_REQD_ACW"`
				IsTicketIDReqdMandatory string   `json:"IS_TICKETID_REQD_MANDATORY"`
				PasswdID                string   `json:"PASSWDID"`
				Passwordtatus           string   `json:"PASSWORD STATUS"`
			} `json:"ACCOUNT LIST,omitempty"`
			// GET_PASSWORD
			Password string `json:"PASSWORD,omitempty"`
		} `json:"details,omitempty"`
	} `json:"operation"`
}

// PMPAPIResultResources specific response for GET_RESOURCES
type PMPAPIResultResources struct {
	Operation struct {
		// name/status
		Name   string `json:"name"`
		Result struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"result"`
		Details []struct {
			// GET_RESOURCES
			NoOfAccounts        string `json:"NOOFACCOUNTS"`
			ResourceDescription string `json:"RESOURCE DESCRIPTION"`
			ResourceID          string `json:"RESOURCE ID"`
			ResourceName        string `json:"RESOURCE NAME"`
			ResourceType        string `json:"RESOURCE TYPE"`
		} `json:"details"`
		TotalRows int `json:"totalRows"`
	} `json:"operation"`
}

// PMPClient provides methods to setup session and get passwords
type PMPClient struct {
	*TinyClient
	LoginURL string
	BaseURL  string
	User     string
	Domain   string
	Org      string
	OrgID    int
	AuthKey  string
	Mode     PMPMode
}

// PMPConfig holds values for PMPClient constructor
type PMPConfig struct {
	LoginURL   string
	Domain     string
	User       string
	Password   string
	Org        string
	System     string
	Account    string
	Ticket     string
	Reason     string
	SetEnv     bool
	IgnoreCert bool
	Verbose    bool
	Debug      bool
}

// PMPEntry holds user/password for system
type PMPEntry struct {
	system   string
	user     string
	password string
}

// String converts it to string
func (e PMPEntry) String() (str string) {
	return e.user + "@" + e.system + " / " + strings.Repeat("*", utf8.RuneCountInString(e.password))
}

// NewPMPClient creates PMPClient
func NewPMPClient(cfg PMPConfig) (pc *PMPClient, err error) {
	u, err := url.Parse(cfg.LoginURL)
	if err != nil {
		log.Fatalln(err)
	}
	tc, err := NewTinyClient(map[string]string{
		"User-Agent":  "Mozilla/5.0 (Linux 6.1; rv:48.0) Gecko/20100101 Firefox/48.0",
		"requestFrom": "pmpmobilenative",
		"clientType":  "12",
	}, cfg.IgnoreCert)
	if err != nil {
		log.Fatalln(err)
	}
	baseURL := u.Scheme + "://" + u.Host
	return &PMPClient{
		TinyClient: tc,
		LoginURL:   cfg.LoginURL,
		BaseURL:    baseURL,
		Domain:     cfg.Domain,
		Org:        cfg.Org,
		Mode:       PMPModePlugin,
	}, err
}

// DoPluginRest do post against rest endpoint and returns unmarshaled json
// TODO: do 'status' check inside; add boolean out param
func (pc *PMPClient) DoPluginRest(u string, method string) (res PMPAPIResult, err error) {
	u = pc.BaseURL + u
	var body string
	var status int
	if method == "POST" {
		body, status, err = pc.Post(u)
	} else if method == "GET" {
		body, status, err = pc.Get(u)
	} else {
		log.Fatalln("Wrong method '" + method + "'")
	}
	if err != nil || status != 200 {
		return
	}

	err = json.Unmarshal([]byte(body), &res)
	Debug("Response:", res)
	return
}

// SetUserDomain gets domain for given user
func (pc *PMPClient) SetUserDomain() (err error) {
	// get userdomain
	u := pc.BaseURL + "/login/AjaxResponse.jsp?RequestType=GetUserDomainName&userName=" + pc.User
	body, status, err := pc.Get(u)
	if err != nil {
		log.Fatalln(err)
	}
	if status == 200 && err == nil {
		pc.Domain = html.UnescapeString(strings.Trim(body, " \t\n"))
	}
	return
}

// loginAPI tries to authenticate via API
func (pc *PMPClient) loginAPI(user string, password string) (success bool, err error) {
	pc.User = user
	// pc.Mode == PMPModePlugin

	// u := pc.BaseURL + "/api/json/request?OPERATION_NAME=GET_AUTHENTICATION_MODE"
	// body, status, err := pc.Post(u)
	// if err != nil || status != 200 {
	// 	log.Panic(err)
	// }

	// var res PMPAPIResult
	// if err = json.Unmarshal([]byte(body), &res); err != nil {
	// 	log.Fatalln(err)
	// }

	res, err := pc.DoPluginRest("/api/json/request?OPERATION_NAME=GET_AUTHENTICATION_MODE", "POST")
	if err != nil {
		log.Fatalln("Unable to call GET_AUTHENTICATION_MODE:", err)
	}
	if res.Operation.Result.Status != "Success" {
		// Can't get auth info, trying to get org name from Web interface
		Debug("[" + res.Operation.Name + "] " + res.Operation.Result.Status + ": " + res.Operation.Result.Message)
		if pc.Domain == "" {
			if err = pc.SetUserDomain(); err != nil {
				log.Panic(err)
			}
		}
		pc.Header["orgName"] = pc.Domain

		// try API again
		res, err = pc.DoPluginRest("/api/json/request?OPERATION_NAME=GET_AUTHENTICATION_MODE", "POST")
		if err != nil {
			log.Fatalln("Unable to call GET_AUTHENTICATION_MODE with orgName set:", err)
		}
		delete(pc.Header, "orgName")
	}
	det := res.Operation.Details
	Debug("PMP Build: " + det.BuildNumber +
		"; FirstFactor: " + det.FirsFactor +
		" SecondFactor: " + det.IsSecondFactorEnabled + " " + det.SecondFactor +
		"; MSP: " + det.MSPEnabled)

	// TODO: implement SecondFactor?
	if strings.ToUpper(det.IsSecondFactorEnabled) == "TRUE" {
		log.Panic("Second Factor is not implemented")
	}

	if strings.ToUpper(det.FirsFactor) == "LOCAL" {
		// nothing for now
		Debug("Doing nothing special for FirsFactor=" + det.FirsFactor)
	} else if strings.ToUpper(det.FirsFactor) == "AD" {
		// check/set domain
		if pc.Domain == "" {
			pc.Domain = det.DefaultDomain
		} else {
			found := false
			list := ""
			for _, d := range det.DomainList {
				list = list + " " + d.DomainName
				if d.DomainName == pc.Domain {
					found = true
				}
			}
			if !found {
				log.Panic("Provided Domain [" + pc.Domain +
					"] is not found in Domain List: " + list)
			}
		}
	} else {
		log.Panic("Unknown Auth Method: " + det.FirsFactor)
	}

	// auth
	u := "/api/json/auth?" +
		"USERNAME=" + user +
		"&PASSWORD=" + password +
		"&FIRSTAUTHMODE=" + det.FirsFactor +
		"&DOMAINNAME=" + pc.Domain
	Debug("Auth URL: " + u)
	// body, status, err = pc.Post(u)
	// if err != nil || status != 200 {
	// 	log.Panic(err)
	// }

	// if err = json.Unmarshal([]byte(body), &res); err != nil {
	// 	log.Fatalln(err)
	// }
	if res, err = pc.DoPluginRest(u, "POST"); err != nil {
		log.Fatalln(err)
	}
	if res.Operation.Result.Status == "Success" {
		det = res.Operation.Details
		pc.AuthKey = det.AuthKey
		Debug("[" + res.Operation.Name + "] " + res.Operation.Result.Status + ": " + res.Operation.Result.Message)
		Info("Hello " + det.Permissions.UserDetails.UserFullName + " (" + det.Permissions.UserDetails.UserEmailID + ")")
	} else {
		log.Panic("[" + res.Operation.Name + "] " + res.Operation.Result.Status + ": " + res.Operation.Result.Message)
	}

	// change org
	Debug("OrgList:")
	found := false
	for _, o := range res.Operation.Details.Permissions.UserDetails.OrgList {
		Debug(o.OrgID, ": "+o.OrgURLName+" = "+o.OrgName)
		if o.OrgURLName == pc.Org {
			pc.Org = o.OrgName
			pc.OrgID = o.OrgID
			pc.Header["orgName"] = pc.Org
			found = true
		}
	}
	if !found {
		log.Panic("Org '" + pc.Org + "' not found")
	}
	return true, nil
}

// loginBrowser submits login form
func (pc *PMPClient) loginBrowser(user string, password string) (success bool, err error) {
	pc.User = user
	var auth string
	// get form input fields
	body, status, err := pc.Get(pc.LoginURL)
	if err != nil {
		log.Fatalln(err)
	}
	// TODO: loginURL can have meta redirect
	// r := regexp.MustCompile(`(?i)<meta http-equiv="refresh" content="\d+;URL=([^"]+)">`)
	// if m := r.FindStringSubmatch("html to parse")[1]; m != nil {
	//   ...
	// }
	if status == 200 && err == nil {
		if pc.Org, err = htmlElementValByID(body, "ORGN_NAME"); err != nil {
			log.Fatalln(err)
		}
		if auth, err = htmlElementValByID(body, "AUTHRULE_NAME"); err != nil {
			log.Fatalln(err)
		}
	} else {
		err = errors.New("Bad status " + string(status) + " for " + pc.LoginURL)
	}

	// get domain
	if pc.Domain == "" {
		if err = pc.SetUserDomain(); err != nil {
			log.Fatalln(err)
		}
	}

	// set domain for AD auth
	if auth != "" && pc.Domain != "" {
		pc.User = pc.Domain + "\\" + pc.User
	}

	// submit login form
	jsessionid := pc.GetCookie(pc.BaseURL, "JSESSIONID")
	u := pc.BaseURL + "/j_security_check;jsessionid=" + jsessionid
	vals := url.Values{
		"BROWSER_NAME":  {"FF"},
		"ORGN_NAME":     {pc.Org},
		"j_username":    {pc.User},
		"username":      {pc.User},
		"domainName":    {pc.Domain},
		"j_password":    {password},
		"AUTHRULE_NAME": {auth},
	}
	_, status, err = pc.PostForm(u, vals)
	if err != nil {
		log.Fatalln(err)
	}
	if status == 200 && err == nil {
		success = true
	}
	Debug("Values:", vals)
	pmpcc := pc.GetCookie(pc.BaseURL, "pmpcc")
	Debug("[", status, "]", "Login", "pmpcc="+pmpcc)
	if pmpcc == "" {
		log.Fatalln(errors.New("Login failed"))
	}
	return
}

// Login to PMP
func (pc *PMPClient) Login(user string, password string) (success bool, err error) {
	pc.User = user
	// try Pluginn first
	defer func() {
		if r := recover(); r != nil {
			Debug("Recovering", r)
			Info("Folling to Browser login")
			success, err = pc.loginBrowser(user, password)
			pc.Mode = PMPModeBrowser
		}
	}()
	switch pc.Mode {
	case PMPModePlugin:
		success, err = pc.loginAPI(user, password)
	case PMPModeBrowser:
		success, err = pc.loginBrowser(user, password)
	default:
		log.Fatalln("Unknown mode", pc.Mode)
	}
	return
}

// LogOut submits login form
func (pc *PMPClient) LogOut() (err error) {
	switch pc.Mode {
	case PMPModePlugin:
		err = pc.logOutPlugin()
	case PMPModeBrowser:
		err = pc.logOutBrowser()
	default:
		log.Fatalln("Unknown mode", pc.Mode)
	}
	return
}

func (pc *PMPClient) logOutPlugin() (err error) {
	// TODO: fix "Password Manager Pro has detected harmful contents in the input"
	t := time.Now().Unix()
	u := "/api/json/request?AUTHTOKEN=" + pc.AuthKey + "&" +
		url.Values{
			"OPERATION_NAME": {"ADD_OFFLINEAUDIT"},
			"INPUT_DATA": {`{ "operation" : { "Details" : [ ` +
				`{ "AUDITTYPE": "USERAUDIT", ` +
				`"USERNAME" : "` + pc.User + `","LOGINUSER":"N/A",` +
				`"OPERATEDTIME":"` + strconv.FormatInt(t, 10) + `",` +
				`"RESOURCENAME":"N/A","ACCOUNTNAME":"N/A","OPERATIONTYPE":"User Logged out",` +
				`"ORGID":"` + strconv.Itoa(pc.OrgID) + `" }]}}`},
		}.Encode()
	res, err := pc.DoPluginRest(u, "POST")
	if err != nil {
		log.Fatalln("Unable to logOut:", err)
	}
	if res.Operation.Result.Status != "Success" {
		Info("[" + res.Operation.Name + "] " + res.Operation.Result.Status + ": " + res.Operation.Result.Message)
	}
	return
}

func (pc *PMPClient) logOutBrowser() (err error) {
	// get session id
	pmpcc := pc.GetCookie(pc.BaseURL, "pmpcc")
	// submit login form
	u := pc.BaseURL + "/jsp/xmlhttp/AjaxResponse.jsp"
	_, status, err := pc.PostForm(u, url.Values{
		"RequestType": {"InvalidateSession"},
		"pmpcp":       {pmpcc},
	})
	if err != nil {
		return
	}
	if status != 200 {
		err = errors.New("Bad status " + string(status) + " for " + u)
	}
	return
}

// GetOrgs checks available Orgs
func (pc *PMPClient) GetOrgs() (orgs map[string]string, err error) {
	// get ORGs
	u := pc.BaseURL + "/ajaxservlet/AjaxServlet?action=searchOrganization"
	resp, status, err := pc.Get(u)
	if err != nil {
		log.Fatalln("Unable to get ORGs:", err)
	}
	if status != 200 {
		err = errors.New("Bad status " + string(status) + " for url: " + u)
	}

	// setup json -> golang mapping
	var data struct {
		Status string `json:"status"`
		List   []struct {
			Label string `json:"label"`
			Value string `json:"value"`
		}
	}
	if err = json.Unmarshal([]byte(resp), &data); err != nil {
		log.Println(err)
	}
	if data.Status == "200" && err == nil {
		orgs = make(map[string]string)
		for _, s := range data.List {
			orgs[s.Label] = s.Value
		}
	} else {
		err = errors.New("Bad status " + data.Status + " for json request")
	}
	Debug("JSON", data)
	return
}

// ChangeOrg changes org if it can
func (pc *PMPClient) ChangeOrg(org string) (err error) {
	if pc.Mode == PMPModePlugin {
		Debug("Org is set during login for Plugin, doing nothing")
		return
	}
	// get/check org
	orgs, err := pc.GetOrgs()
	if err != nil {
		log.Fatalln(err)
	}
	orgID, exists := orgs[org]
	if !exists {
		err = errors.New("Cannot find id for org '" + org + "'")
		return
	}

	// get session id
	pmpcc := pc.GetCookie(pc.BaseURL, "pmpcc")
	// change ORG
	u := pc.BaseURL + "/jsp/xmlhttp/OrgAjaxResponse.jsp?RequestType=organizationChange&SUBREQUEST=XMLHTTP"
	body, status, err := pc.PostForm(u, url.Values{
		"ORGID": {orgID},
		"pmpcp": {pmpcc},
	})
	if status != 200 {
		err = errors.New("Failed to change org to '" + org + "'")
	}
	Debug("[", status, "]", body)
	return
}

// GetPassword changes org if it can
func (pc *PMPClient) GetPassword(entry *PMPEntry, reason string, addreason string) (err error) {
	switch pc.Mode {
	case PMPModePlugin:
		pc.getPasswordPlugin(entry, reason, addreason)
	case PMPModeBrowser:
		pc.getPasswordBrowser(entry, reason, addreason)
	default:
		log.Fatalln("Unknown mode", pc.Mode)
	}
	return
}

func (pc *PMPClient) getPasswordPlugin(entry *PMPEntry, reason string, addreason string) (err error) {
	// search for systems
	Debug("Getting systems/resources list")
	u := "/api/json/request" +
		"?AUTHTOKEN=" + pc.AuthKey +
		"&OPERATION_NAME=GET_RESOURCES" +
		`&INPUT_DATA={"operation":{"Details":{` +
		`"SEARCHCOLUMN":"RESOURCENAME",` +
		`"SEARCHVALUE":"` + entry.system + `",` +
		`"VIEWTYPE":"ALLMYPASSWORD","STARTINDEX":"0",` +
		`"LIMIT":"50","SEARCHTYPE":"RESOURCE"}}}`
	var resr PMPAPIResultResources
	body, status, err := pc.Post(pc.BaseURL + u)
	if err != nil || status != 200 {
		log.Fatalln("Unable to call GET_RESOURCES:", err)
	}
	if err = json.Unmarshal([]byte(body), &resr); err != nil {
		log.Fatalln("Unable to parse response:", err)
	}
	if resr.Operation.Result.Status != "Success" {
		return errors.New("Unable to get systems")
	}

	Info("Found systems:")
	var id string
	for i, r := range resr.Operation.Details {
		Info("[", i, "] "+r.ResourceID+": "+r.ResourceName+
			" ("+r.ResourceType+") with "+r.NoOfAccounts+" account(s)")
		// search for exact name or get first one
		if i == 0 || r.ResourceName == entry.system {
			id = r.ResourceID
			entry.system = r.ResourceName
		}
	}
	// search for accounts
	Debug("Getting accounts for resource " + id)
	u = "/api/json/request" +
		"?AUTHTOKEN=" + pc.AuthKey +
		"&OPERATION_NAME=GET_RESOURCEACCOUNTLIST" +
		`&INPUT_DATA={"operation":{"Details":{` +
		`"SEARCHVALUE":"` + entry.user + `",` +
		`"SEARCHTYPE":"RESOURCE","SEARCHCOLUMN":"ALL","LIMIT":"50",` +
		`"STARTINDEX":"0",` +
		`"RESOURCEID":"` + id + `",` +
		`"VIEWTYPE":"ALLMYPASSWORD"}}}`
	res, err := pc.DoPluginRest(u, "POST")
	if err != nil {
		log.Fatalln("Unable to call GET_RESOURCEACCOUNTLIST:", err)
	}
	if res.Operation.Result.Status != "Success" {
		Info("[" + res.Operation.Name + "] " + res.Operation.Result.Status + ": " + res.Operation.Result.Message)
		return errors.New("Unable to get account info")
	}
	Info("Found accounts:")
	for i, a := range res.Operation.Details.AccountList {
		Info("[", i, "] "+a.AccountID+": "+a.AccountName+
			" ( passid: "+a.PasswdID+
			"; ticket: ", a.IsTicketIDReqd, "; reson:", a.IsReasonRequired, ")")
		// search for exact name or get first one
		if i == 0 || a.AccountName == entry.user {
			id = a.AccountID
			entry.user = a.AccountName
		}
	}

	// get password, finally
	Debug("Getting password for account " + id)
	u = "/api/json/request?AUTHTOKEN=" + pc.AuthKey + "&" +
		url.Values{
			"OPERATION_NAME": {"GET_PASSWORD"},
			"INPUT_DATA": {`{"operation":{"Details":{` +
				`"PASSWDID":"` + id + `", "REASON":"` + addreason + `", "TICKETID":"` + reason + `"}}}"`},
		}.Encode()
	res, err = pc.DoPluginRest(u, "GET")
	if err != nil {
		log.Fatalln("Unable to call GET_PASSWORD:", err)
	}
	if res.Operation.Result.Status != "Success" {
		Info("[" + res.Operation.Name + "] " + res.Operation.Result.Status + ": " + res.Operation.Result.Message)
		return errors.New("Unable to get password")
	}
	entry.password = res.Operation.Details.Password

	return
}

func (pc *PMPClient) getPasswordBrowser(entry *PMPEntry, reason string, addreason string) (err error) {
	// get session id
	pmpcc := pc.GetCookie(pc.BaseURL, "pmpcc")
	// query password
	u := pc.BaseURL + "/jsp/xmlhttp/PasswdRetriveAjaxResponse.jsp?RequestType=PasswordRetrived"
	resp, status, err := pc.PostForm(u, url.Values{
		"resource":  {entry.system},
		"account":   {entry.user},
		"REASON":    {reason},
		"ADDREASON": {addreason},
		"pmpcp":     {pmpcc},
	})
	if status != 200 {
		err = errors.New("Failed to get password for: " + entry.String() + ", response: " + resp)
	} else {
		entry.password = strings.Trim(resp, " \n\t")
	}
	return
}

// -----------------------------------------------------------------------------
// HTTP Client (kinda)
// -----------------------------------------------------------------------------

// TinyClient tries to simplify http requests and session management
// suitable for really simple http communication
// NOT thread safe
type TinyClient struct {
	Client    *http.Client
	Header    map[string]string
	cookieJar *cookiejar.Jar
}

// NewTinyClient creates new client
// if IgnoreCert=true => ignores ssl certificates
func NewTinyClient(header map[string]string, IgnoreCert bool) (tc *TinyClient, err error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return
	}

	// ignore untrusted certs
	if IgnoreCert {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr, Jar: jar}
		tc = &TinyClient{client, header, jar}
	} else {
		client := &http.Client{Jar: jar}
		tc = &TinyClient{client, header, jar}
	}
	return tc, err
}

// GetCookie returns value of cookie for given url,
// emty string if not find
func (c *TinyClient) GetCookie(rawURL string, name string) (value string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Fatalln(err)
	}
	for _, cookie := range c.cookieJar.Cookies(u) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// DoReq submits 'generic' request
func (c *TinyClient) DoReq(req *http.Request) (str string, status int, err error) {
	Debug("Request:", req.URL)
	Debug("Headers:", req.Header)
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	status = resp.StatusCode
	body := resp.Body
	defer body.Close()
	b, err := ioutil.ReadAll(body)
	Debug("Status :", status)
	if err != nil {
		return
	}
	return string(b), status, nil
}

// prepareReq deals with agent and extra headers
func (c *TinyClient) prepareReq(req *http.Request) {
	for k, v := range c.Header {
		req.Header.Add(k, v)
	}
}

// PostForm submits form provided as url.Values
func (c *TinyClient) PostForm(url string, vals url.Values) (body string, status int, err error) {
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(vals.Encode()))
	if err != nil {
		return
	}
	c.prepareReq(req)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return c.DoReq(req)
}

// Post submits HTTP GET for given URL
func (c *TinyClient) Post(url string) (body string, status int, err error) {
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return
	}
	c.prepareReq(req)
	return c.DoReq(req)
}

// Get submits HTTP GET for given URL
func (c *TinyClient) Get(url string) (body string, status int, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	c.prepareReq(req)
	return c.DoReq(req)
}

// -----------------------------------------------------------------------------
// html helpers
// -----------------------------------------------------------------------------

func htmlGetElementByID(id string, n *xhtml.Node) (element *xhtml.Node, ok bool) {
	for _, a := range n.Attr {
		if a.Key == "id" && a.Val == id {
			return n, true
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if element, ok = htmlGetElementByID(id, c); ok {
			return
		}
	}
	return
}

func htmlElementValByID(htmlStr string, name string) (str string, err error) {
	root, err := xhtml.Parse(strings.NewReader(htmlStr))
	if err != nil {
		fmt.Println(err)
	}
	element, ok := htmlGetElementByID(name, root)
	if !ok {
		return
	}
	for _, a := range element.Attr {
		if a.Key == "value" {
			str = a.Val
			return
		}
	}
	return
}

// -----------------------------------------------------------------------------
// Other helpers
// -----------------------------------------------------------------------------

func printHelp() {
	fmt.Println("Version:", VERSION, "( for", VERSIONAPI, ")")
	fmt.Println("Usage  :")
	fmt.Println("  pmpcli l=<login_url> [d=<domain>] u=<user> p=<pass> o=<org> s=<system> a=<account> t=<ticket> r=<reason> [cert=ignore] [<env>|<verbose>|<debug>]")
	fmt.Println("Example:")
	fmt.Println("  pmpcli l=https://127.0.0.1:7272 u=user p=pass o=org1 s=serv a=root t=inc1234 r=check # get password")
	fmt.Println("  eval $(pmpcli .... o=org1 s=serv a=root ... env)                                     # set env vars with password")
	fmt.Println("  pmpcli l=https://127.0.0.1:7272 u=user p=pass o=org1 i=serv a=root                   # search")
	fmt.Println("Help:")
	fmt.Println("  s|i - system name has alias 'i'")
	fmt.Println("  env - will print commands to setup bash env")
}

func parseArgs(args []string) (cfg PMPConfig) {
	//fmt.Println(len(os.Args))
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}
	for _, a := range os.Args[1:] {
		Debug("arg:", a)
		s := strings.SplitN(a, "=", 2)
		if s == nil || len(s) == 1 {
			switch a {
			case "env":
				cfg.SetEnv = true
			case "debug":
				cfg.Debug = true
			case "verbose":
				cfg.Verbose = true
			default:
				log.Fatalln("ERROR: wrong arg", a)
			}
		} else {
			k := s[0]
			v := s[1]
			// synonyms
			if k == "i" {
				k = "s"
			}
			switch k {
			case "l":
				Debug("login:", v)
				cfg.LoginURL = v
			case "d":
				Debug("domain:", v)
				cfg.Domain = v
			case "u":
				Debug("user:", v)
				cfg.User = v
			case "p":
				Debug("password:", v)
				cfg.Password = v
			case "o":
				Debug("org:", v)
				cfg.Org = v
			case "s":
				Debug("system:", v)
				cfg.System = v
			case "a":
				Debug("account:", v)
				cfg.Account = v
			case "t":
				Debug("ticket:", v)
				cfg.Ticket = v
			case "r":
				Debug("reason:", v)
				cfg.Reason = v
			// TOOD: add PMPMode
			case "cert":
				Debug("certificate:", v)
				if v == "ignore" {
					cfg.IgnoreCert = true
				}
			default:
				log.Fatalln("ERROR: Wrong option:", a)
			}
		}
	}
	return
}

func getPasswords(cfg PMPConfig) {
	pc, err := NewPMPClient(cfg)
	if err != nil {
		log.Fatalln(err)
	}
	Debug("LOGIN")
	success, err := pc.Login(cfg.User, cfg.Password)
	if err != nil || !success {
		log.Fatalln(err)
	}
	Debug("CHANGE ORG")
	if err = pc.ChangeOrg(cfg.Org); err != nil {
		log.Fatalln(err)
	}
	Debug("GET PASSWORD")
	entry := &PMPEntry{system: cfg.System, user: cfg.Account}
	// TODO: redo for multiple results
	// TODO: browser: get password even without reason/ticket
	// TODO: plugin: check if reason/password needed and do just search if not provided
	if err = pc.GetPassword(entry, cfg.Ticket, cfg.Reason); err != nil {
		log.Fatalln(err)
	}
	Debug("RESULTS")
	if cfg.SetEnv {
		// TODO: need to redirect stdout to stderr (to get more control over what goes to stdout)
		v := entry.system + "_" + entry.user
		// sanitize variable name
		re := regexp.MustCompile("[[:alnum:]_]+")
		v = strings.Join(re.FindAllString(v, -1), "_")
		// sanitize password
		p := strings.Replace(entry.password, "'", `'"'"'`, -1)
		// print env
		fmt.Println("echo '# Setting " + v +
			" for " + entry.user + " @ " + entry.system +
			"'; " + v + "='" + p + "'")
	} else {
		fmt.Println(entry.user + " @ " + entry.system + " / " + entry.password)
	}
	if pc.LogOut(); err != nil {
		log.Fatalln(err)
	}
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	log.SetFlags(0)
	cfg := parseArgs(os.Args)
	if cfg.Verbose {
		VERBOSE = true
	}
	if cfg.Debug {
		DEBUG = true
	}
	Debug("PMPConfig:", cfg)
	getPasswords(cfg)
}
