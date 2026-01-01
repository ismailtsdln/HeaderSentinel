package rules

// RiskLevel represents the severity of a security issue.
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
	RiskInfo     RiskLevel = "INFO"
)

// SecurityRule defines a header security check.
type SecurityRule struct {
	Header         string
	CheckName      string
	Risk           RiskLevel
	Description    string
	Recommendation string
	Exploit        string
}

// SecurityHeaders contains the list of rules to check.
var SecurityHeaders = []SecurityRule{
	{
		Header:         "Content-Security-Policy",
		CheckName:      "Insecure CSP",
		Risk:           RiskHigh,
		Description:    "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.",
		Recommendation: "Configure a strong CSP policy to restrict where resources can be loaded from.",
		Exploit:        "XSS, Clickjacking, Data injection.",
	},
	{
		Header:         "Strict-Transport-Security",
		CheckName:      "Missing HSTS",
		Risk:           RiskMedium,
		Description:    "HTTP Strict Transport Security (HSTS) informs browsers that the site should only be accessed using HTTPS.",
		Recommendation: "Set a Strict-Transport-Security header with a long max-age and includeSubDomains.",
		Exploit:        "Man-in-the-Middle (MITM) attacks, SSL stripping.",
	},
	{
		Header:         "X-Frame-Options",
		CheckName:      "Missing XFO",
		Risk:           RiskMedium,
		Description:    "X-Frame-Options (XFO) indicates whether or not a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>.",
		Recommendation: "Use 'DENY' or 'SAMEORIGIN' to prevent clickjacking.",
		Exploit:        "Clickjacking.",
	},
	{
		Header:         "X-Content-Type-Options",
		CheckName:      "Missing XCTO",
		Risk:           RiskLow,
		Description:    "X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type.",
		Recommendation: "Set X-Content-Type-Options to 'nosniff'.",
		Exploit:        "MIME-sniffing based attacks.",
	},
	{
		Header:         "Referrer-Policy",
		CheckName:      "Insecure Referrer Policy",
		Risk:           RiskLow,
		Description:    "The Referrer-Policy HTTP header controls how much referrer information (sent via the Referer header) should be included with requests.",
		Recommendation: "Use a safer policy like 'strict-origin-when-cross-origin' or 'no-referrer'.",
		Exploit:        "Information disclosure via Referer header.",
	},
	{
		Header:         "Permissions-Policy",
		CheckName:      "Missing Permissions Policy",
		Risk:           RiskLow,
		Description:    "Permissions-Policy allows developers to selectively enable, disable, and modify the behavior of certain APIs and web features in the browser.",
		Recommendation: "Implement a restrictive Permissions-Policy to reduce attack surface.",
		Exploit:        "Unauthorized access to browser APIs (camera, geolocation, etc.).",
	},
	{
		Header:         "Server",
		CheckName:      "Information Disclosure (Server)",
		Risk:           RiskLow,
		Description:    "The Server header contains information about the software used by the origin server to handle the request.",
		Recommendation: "Configure the server to remove or minimize the Server header.",
		Exploit:        "Banner grabbing, identifying vulnerable server versions.",
	},
	{
		Header:         "X-Powered-By",
		CheckName:      "Information Disclosure (X-Powered-By)",
		Risk:           RiskLow,
		Description:    "The X-Powered-By header provides information about the technology used (e.g., PHP, ASP.NET).",
		Recommendation: "Remove the X-Powered-By header.",
		Exploit:        "Identifying backend technology stack for targeted attacks.",
	},
	{
		Header:         "Cross-Origin-Opener-Policy",
		CheckName:      "Insecure COOP",
		Risk:           RiskLow,
		Description:    "COOP helps to isolate your document from other origin's documents to prevent certain types of attacks like Spectre.",
		Recommendation: "Set COOP to 'same-origin'.",
		Exploit:        "Spectre-style attacks, cross-window information leaks.",
	},
	{
		Header:         "Cross-Origin-Embedder-Policy",
		CheckName:      "Insecure COEP",
		Risk:           RiskLow,
		Description:    "COEP prevents a document from loading any cross-origin resources that do not explicitly grant the document permission.",
		Recommendation: "Set COEP to 'require-corp' or 'credentialless'.",
		Exploit:        "Loading unauthorized cross-origin resources.",
	},
	{
		Header:         "Cross-Origin-Resource-Policy",
		CheckName:      "Insecure CORP",
		Risk:           RiskLow,
		Description:    "CORP allows you to control which origins can load your resources.",
		Recommendation: "Set CORP to 'same-origin' or 'same-site'.",
		Exploit:        "Speculative side-channel attacks (e.g., Spectre).",
	},
	{
		Header:         "Set-Cookie",
		CheckName:      "Insecure Cookie (Missing HttpOnly)",
		Risk:           RiskMedium,
		Description:    "The HttpOnly flag help to prevent XSS attacks from stealing cookies.",
		Recommendation: "Add the 'HttpOnly' flag to all sensitive cookies.",
		Exploit:        "Cookie theft via XSS.",
	},
	{
		Header:         "Set-Cookie",
		CheckName:      "Insecure Cookie (Missing Secure)",
		Risk:           RiskMedium,
		Description:    "The Secure flag ensures that the cookie is only sent over HTTPS.",
		Recommendation: "Add the 'Secure' flag to all sensitive cookies.",
		Exploit:        "Cookie interception over insecure connections (MITM).",
	},
	{
		Header:         "Set-Cookie",
		CheckName:      "Insecure Cookie (Missing SameSite)",
		Risk:           RiskLow,
		Description:    "The SameSite flag helps to protect against CSRF attacks.",
		Recommendation: "Add 'SameSite=Lax' or 'SameSite=Strict' to your cookies.",
		Exploit:        "Cross-Site Request Forgery (CSRF).",
	},
}
