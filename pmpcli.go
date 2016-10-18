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
	"strings"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
)

// -----------------------------------------------------------------------------
// Version
// -----------------------------------------------------------------------------

// BUILD number
const BUILD = "201610181947"

// VERSION of this piece of ***
const VERSION = "0.1.2." + BUILD

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

// PMPClient provides methods to setup session and get passwords
type PMPClient struct {
	*TinyClient
	LoginURL string
	BaseURL  string
	User     string
	Domain   string
	Org      string
	mode     PMPMode
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
		mode:       PMPModePlugin,
	}, err
}

// SetUserDomain gets domain for given user
func (pc *PMPClient) SetUserDomain() (err error) {
	// get userdomain
	u := pc.BaseURL + "/login/AjaxResponse.jsp?RequestType=GetUserDomainName&userName=" + pc.User
	Info("Request:", u)
	body, status, err := pc.Get(u)
	if err != nil {
		log.Fatalln(err)
	}
	if status == 200 && err == nil {
		pc.Domain = html.UnescapeString(strings.Trim(body, " \t\n"))
	}
	return
}

// Login submits login form
func (pc *PMPClient) Login(user string, password string) (success bool, err error) {
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
	Info("Request:", u)
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

// LogOut submits login form
func (pc *PMPClient) LogOut() (err error) {
	// get session id
	pmpcc := pc.GetCookie(pc.BaseURL, "pmpcc")
	// submit login form
	u := pc.BaseURL + "/jsp/xmlhttp/AjaxResponse.jsp"
	Info("Request:", u)
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
	Info("Request:", u)
	resp, status, err := pc.Get(u)
	if err != nil {
		log.Fatalln(err)
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
	Info("Request:", u)
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
	// get session id
	pmpcc := pc.GetCookie(pc.BaseURL, "pmpcc")
	// query password
	u := pc.BaseURL + "/jsp/xmlhttp/PasswdRetriveAjaxResponse.jsp?RequestType=PasswordRetrived"
	Info("Request:", u)
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
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	status = resp.StatusCode
	body := resp.Body
	defer body.Close()
	b, err := ioutil.ReadAll(body)
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
	fmt.Println("  pmpcli l=https://127.0.0.1:7272 u=user p=pass o=org1 s=serv a=root t=inc1234 r=check")
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
	success, err := pc.Login(cfg.User, cfg.Password)
	if err != nil || !success {
		log.Fatalln(err)
	}
	if err = pc.ChangeOrg(cfg.Org); err != nil {
		log.Fatalln(err)
	}
	entry := &PMPEntry{system: cfg.System, user: cfg.Account}
	if err = pc.GetPassword(entry, cfg.Ticket, cfg.Reason); err != nil {
		log.Fatalln(err)
	}
	if cfg.SetEnv {
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
