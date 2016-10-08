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
	"strings"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
)

// -----------------------------------------------------------------------------
// PMP Client
// -----------------------------------------------------------------------------

// PMPClient provides methods to setup session and get passwords
type PMPClient struct {
	*TinyClient
	LoginURL string
	BaseURL  string
	User     string
	Domain   string
	Org      string
	//TODO: logger as dependency/part of struct/constructor
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
// if not secure => ignores ssl certs
func NewPMPClient(LoginURL string, secure bool) (pc *PMPClient, err error) {
	u, err := url.Parse(LoginURL)
	if err != nil {
		log.Fatalln(err)
	}
	tc, err := NewTinyClient(secure)
	if err != nil {
		log.Fatalln(err)
	}
	return &PMPClient{tc, LoginURL, u.Scheme + "://" + u.Host, "", "", ""}, err
}

// SetUserDomain gets domain for given user
func (pc *PMPClient) SetUserDomain() (err error) {
	// get userdomain
	u := pc.BaseURL + "/login/AjaxResponse.jsp?RequestType=GetUserDomainName&userName=" + pc.User
	if VERBOSE {
		log.Println("Request:", u)
	}
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

	// submit login form
	jsessionid := pc.GetCookie(pc.BaseURL, "JSESSIONID")
	u := pc.BaseURL + "/j_security_check;jsessionid=" + jsessionid
	if VERBOSE {
		log.Println("Request:", u)
	}
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
	if DEBUG {
		log.Println("Values:", vals)
		log.Println("[", status, "]", "Login", "pmpcc="+pc.GetCookie(pc.BaseURL, "pmpcc"))
	}
	return
}

// LogOut submits login form
func (pc *PMPClient) LogOut() (err error) {
	// get session id
	pmpcc := pc.GetCookie(pc.BaseURL, "pmpcc")
	// submit login form
	u := pc.BaseURL + "/jsp/xmlhttp/AjaxResponse.jsp"
	if VERBOSE {
		log.Println("Request:", u)
	}
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
	if VERBOSE {
		log.Println("Request:", u)
	}
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
	if DEBUG {
		log.Println("JSON", data)
	}
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
	if VERBOSE {
		log.Println("Request:", u)
	}
	body, status, err := pc.PostForm(u, url.Values{
		"ORGID": {orgID},
		"pmpcp": {pmpcc},
	})
	if status != 200 {
		err = errors.New("Failed to change org to '" + org + "'")
	}
	if DEBUG {
		log.Println("[", status, "]", body)
	}
	return
}

// GetPassword changes org if it can
func (pc *PMPClient) GetPassword(entry *PMPEntry, reason string, addreason string) (err error) {
	// get session id
	pmpcc := pc.GetCookie(pc.BaseURL, "pmpcc")
	// query password
	u := pc.BaseURL + "/jsp/xmlhttp/PasswdRetriveAjaxResponse.jsp?RequestType=PasswordRetrived"
	if VERBOSE {
		log.Println("Request:", u)
	}
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
	UserAgent string
	cookieJar *cookiejar.Jar
}

// NewTinyClient creates new client
// if secure=false => ignores ssl certificates
func NewTinyClient(secure bool) (tc *TinyClient, err error) {
	// FireFox is default UserAgent
	const agent = "User-Agent: Mozilla/5.0 (Linux 6.1; rv:48.0) Gecko/20100101 Firefox/48.0"

	jar, err := cookiejar.New(nil)
	if err != nil {
		return
	}

	// ignore untrusted certs
	if secure {
		client := &http.Client{Jar: jar}
		tc = &TinyClient{client, agent, jar}
	} else {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr, Jar: jar}
		tc = &TinyClient{client, agent, jar}
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

// PostForm submits form provided as url.Values
func (c *TinyClient) PostForm(url string, vals url.Values) (body string, status int, err error) {
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(vals.Encode()))
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", c.UserAgent)
	return c.DoReq(req)
}

// Get submits HTTP GET for given URL
func (c *TinyClient) Get(url string) (body string, status int, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("User-Agent", c.UserAgent)
	return c.DoReq(req)
}

func tinyClientUsage() {
	client := &TinyClient{}
	client.UserAgent = "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0"
	rawURL := os.Args[1]

	resp, status, err := client.PostForm(rawURL, url.Values{"custname": {"lalala"}})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("status:", status, "body:", resp)

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
// Main
// -----------------------------------------------------------------------------

// DEBUG is debug
const DEBUG = false

// VERBOSE output
const VERBOSE = false

// BUILD number
const BUILD ="201610081018"

// VERSION of this piece of ***
const VERSION = "0.1.0." + BUILD

// VERSIONAPI engine/plugin versions
const VERSIONAPI = "engine: 8.5.0.8502 / plugin: 1.0.2.4"

func main() {
	if len(os.Args) != 9 {
		fmt.Println("Version:", VERSION, "( for", VERSIONAPI, ")")
		fmt.Println("Usage  :")
		fmt.Println("  pmpcli <login_url> <user> <pass> <org> <system> <account> <ticket> <reason>")
		fmt.Println("Example:")
		fmt.Println("  pmpcli https://127.0.0.1:7272 user pass org1 serv root inc1234 check")
		return
	}
	rawurl := os.Args[1]
	user := os.Args[2]
	pass := os.Args[3]
	org := os.Args[4]
	system := os.Args[5]
	account := os.Args[6]
	ticket := os.Args[7]
	reason := os.Args[8]

	pc, err := NewPMPClient(rawurl, false)
	if err != nil {
		log.Fatalln(err)
	}
	success, err := pc.Login(user, pass)
	if err != nil || !success {
		log.Fatalln(err)
	}
	if err = pc.ChangeOrg(org); err != nil {
		log.Fatalln(err)
	}
	entry := &PMPEntry{system: system, user: account}
	if err = pc.GetPassword(entry, ticket, reason); err != nil {
		log.Fatalln(err)
	}
	fmt.Println(entry.user + " @ " + entry.system + " / " + entry.password)
	if pc.LogOut(); err != nil {
		log.Fatalln(err)
	}
}
