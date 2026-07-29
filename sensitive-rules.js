"use strict";

const SENSITIVE_RULES = [
  // ═══════════════════════════════════════════════════════════════
  //  Tokens & Keys
  // ═══════════════════════════════════════════════════════════════
  { id: "aws-access-key", cat: "Tokens & Keys", desc: "AWS Access Key ID", regex: "A(BIA|CCA|GPA|I(DA|PA)|KIA|N(PA|VA)|PKA|ROA|S(CA|IA))[a-zA-Z0-9]{16,17}(?![a-zA-Z0-9+/=])", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "aws-secret-key", cat: "Tokens & Keys", desc: "AWS Secret Access Key", regex: "aws([^;]{0,32}?)['\"][0-9a-zA-Z/+=]{40}['\"]", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "amazon-mws-auth", cat: "Tokens & Keys", desc: "Amazon MWS Auth Token", regex: "amzn\\.mws\\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "google-api-key", cat: "Tokens & Keys", desc: "Google API Key", regex: "AIza[0-9A-Za-z\\-_]{35}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "google-oauth-token", cat: "Tokens & Keys", desc: "Google OAuth Access Token", regex: "ya29\\.[0-9A-Za-z\\-_]{32,48}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "google-oauth-client-id", cat: "Tokens & Keys", desc: "Google OAuth Client ID", regex: "\\.apps\\.googleusercontent\\.com", refiner: "\\d{1,20}-\\w{32}$", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "google-oauth-client-secret", cat: "Tokens & Keys", desc: "Google OAuth Client Secret", regex: "GOCSPX-[0-9a-zA-Z\\-_]{28}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "mailgun-api-key", cat: "Tokens & Keys", desc: "MailGun API Key", regex: "key-[0-9a-f]{32}(?!\\w)", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "nuget-api-key", cat: "Tokens & Keys", desc: "NuGet API Key", regex: "oy2[a-z0-9]{43}(?![a-z0-9])", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "sendgrid-api-key", cat: "Tokens & Keys", desc: "SendGrid API Key", regex: "SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "slack-token", cat: "Tokens & Keys", desc: "Slack Token", regex: "x(ox[psboare]|app)(-[a-zA-Z0-9]{1,64}){1,5}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "square-token", cat: "Tokens & Keys", desc: "Square Token", regex: "sq0(atp|csp|idp)-[0-9A-Za-z\\-_]{22,43}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "stripe-api-key", cat: "Tokens & Keys", desc: "Stripe API Key", regex: "[sr]k_(live|test)_[0-9a-zA-Z]{24}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "stripe-webhook-secret", cat: "Tokens & Keys", desc: "Stripe Webhook Secret", regex: "whsec_[0-9a-zA-Z]{32}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "twilio-account-sid", cat: "Tokens & Keys", desc: "Twilio Account SID", regex: "SK[0-9a-zA-Z]{32}(?![a-zA-Z0-9+/=?_%)])", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "github-token", cat: "Tokens & Keys", desc: "Github Token", regex: "gh[pousr]_[A-Za-z0-9]{36}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "github-fine-grained-pat", cat: "Tokens & Keys", desc: "Github fine-grained PAT", regex: "github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}", sections: ["resp_body", "resp_headers"], severity: "critical" },
  { id: "openai-api-key", cat: "Tokens & Keys", desc: "OpenAI API Key", regex: "sk-[a-zA-Z0-9]{40,128}(?![\\w\\-])", sections: ["resp_body", "resp_headers"], severity: "critical" },

  // ═══════════════════════════════════════════════════════════════
  //  General Secrets
  // ═══════════════════════════════════════════════════════════════
  { id: "pem-certificate", cat: "General Secrets", desc: "PEM/Certificate", regex: "-----BEGIN", sections: ["resp_body", "resp_headers"], severity: "high" },
  { id: "generic-api-key", cat: "General Secrets", desc: "Generic API Key", regex: "api.{0,5}key[^&|;?,]{0,32}?['\"][a-zA-Z0-9_\\-+=\\/\\\\]{10,}['\"]", sections: ["resp_body", "resp_headers"], severity: "high" },
  { id: "generic-secret", cat: "General Secrets", desc: "Generic Secret", regex: "secret[^&|;?,]{0,32}?['\"][a-zA-Z0-9_\\-+=\\/\\\\]{10,}['\"]", sections: ["resp_body", "resp_headers"], severity: "high" },
  { id: "env-file-ref", cat: "General Secrets", desc: ".env file reference", regex: "\\.env", sections: ["resp_body", "resp_headers"], severity: "medium" },
  { id: "private-ipv4", cat: "General Secrets", desc: "Private IPv4", regex: "1(0(\\.[0-2]\\d{0,2}){3}|27(\\.[0-2]\\d{0,2}){3}|92\\.168(\\.[0-2]\\d{0,2}){2}|72\\.(1[6-9]|2\\d|3[0-2])(\\.[0-2]\\d{0,2}){2})(?![\\d.])", sections: ["resp_body", "resp_headers"], severity: "medium" },
  { id: "email", cat: "General Secrets", desc: "Email", regex: "[a-zA-Z0-9]@[a-zA-Z0-9\\-\\.]{3,128}\\.[a-zA-Z0-9]{2,32}(?![\\w\\\\])", sections: ["resp_body", "resp_headers"], severity: "medium" },

  // ═══════════════════════════════════════════════════════════════
  //  Cloud & Webhooks
  // ═══════════════════════════════════════════════════════════════
  { id: "slack-webhook", cat: "Cloud & Webhooks", desc: "Slack Webhook", regex: "hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}", sections: ["resp_body", "req_url"], severity: "medium" },
  { id: "ms-teams-webhook-connector", cat: "Cloud & Webhooks", desc: "MS Teams Webhook (connector)", regex: "outlook\\.office(365)?\\.com/webhook/[\\w\\-@]{1,128}", sections: ["resp_body", "req_url"], severity: "medium" },
  { id: "ms-teams-webhook-incoming", cat: "Cloud & Webhooks", desc: "MS Teams Webhook (incoming)", regex: "\\.webhook\\.office\\.com", sections: ["resp_body", "req_url"], severity: "medium" },
  { id: "firebase-url", cat: "Cloud & Webhooks", desc: "Firebase URL", regex: "\\.(firebase(io\\.com|database\\.app))", sections: ["resp_body", "req_url"], severity: "high" },
  { id: "aws-s3-bucket", cat: "Cloud & Webhooks", desc: "AWS S3 Bucket", regex: "s3(\\.dualstack|-acce(lerate|sspoint))?\\.([a-z]{1,8}-[a-z]{1,16}-\\d{1,3}\\.)?amazonaws\\.com", sections: ["resp_body", "req_url"], severity: "high" },
  { id: "azure-blob-storage", cat: "Cloud & Webhooks", desc: "Azure Blob Storage", regex: "blob\\.core\\.windows\\.net", sections: ["resp_body", "req_url"], severity: "high" },
  { id: "gcloud-storage", cat: "Cloud & Webhooks", desc: "Google Cloud Storage", regex: "gs://[a-z\\d\\-]{3,63}", sections: ["resp_body", "req_url"], severity: "high" },
  { id: "amazon-arn", cat: "Cloud & Webhooks", desc: "Amazon ARN", regex: "arn:aws(-(cn|us-gov|iso-[bcd]))?:[\\w/.\\-]{1,63}:([\\w/.\\-]{0,63}:){2}([\\w:/.\\-]{0,1023})", sections: ["resp_body", "req_url"], severity: "high" },

  // ═══════════════════════════════════════════════════════════════
  //  Sensitive Files
  // ═══════════════════════════════════════════════════════════════
  { id: "file-agilekeychain", cat: "Sensitive Files", desc: "1Password Keychain (.agilekeychain)", regex: "\\.agilekeychain(?:[?#]|$)", sections: ["req_url"], severity: "critical" },
  { id: "file-asa", cat: "Sensitive Files", desc: "ASP config (.asa)", regex: "\\.asa(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-keychain", cat: "Sensitive Files", desc: "macOS Keychain (.keychain)", regex: "\\.keychain(?:[?#]|$)", sections: ["req_url"], severity: "critical" },
  { id: "file-cscfg", cat: "Sensitive Files", desc: "Azure config (.cscfg)", regex: "\\.cscfg(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-bak", cat: "Sensitive Files", desc: "Backup file (.bak)", regex: "\\.bak(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-cer", cat: "Sensitive Files", desc: "Certificate (.cer)", regex: "\\.cer(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-crt", cat: "Sensitive Files", desc: "Certificate (.crt)", regex: "\\.crt(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-p7b", cat: "Sensitive Files", desc: "Certificate (.p7b)", regex: "\\.p7b(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-zip", cat: "Sensitive Files", desc: "Archive (.zip)", regex: "\\.zip(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-tar", cat: "Sensitive Files", desc: "Archive (.tar)", regex: "\\.tar(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-gz", cat: "Sensitive Files", desc: "Archive (.gz)", regex: "\\.gz(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-tgz", cat: "Sensitive Files", desc: "Archive (.tgz)", regex: "\\.tgz(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-rar", cat: "Sensitive Files", desc: "Archive (.rar)", regex: "\\.rar(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-config", cat: "Sensitive Files", desc: "Config file (.config)", regex: "\\.config(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-dayone", cat: "Sensitive Files", desc: "Day One journal (.dayone)", regex: "\\.dayone(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-docx", cat: "Sensitive Files", desc: "Document (.docx)", regex: "\\.docx(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-doc", cat: "Sensitive Files", desc: "Document (.doc)", regex: "\\.doc(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-rtf", cat: "Sensitive Files", desc: "Document (.rtf)", regex: "\\.rtf(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-xlsx", cat: "Sensitive Files", desc: "Spreadsheet (.xlsx)", regex: "\\.xlsx(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-xls", cat: "Sensitive Files", desc: "Spreadsheet (.xls)", regex: "\\.xls(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-csv", cat: "Sensitive Files", desc: "Spreadsheet (.csv)", regex: "\\.csv(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-gnucash", cat: "Sensitive Files", desc: "GnuCash (.gnucash)", regex: "\\.gnucash(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-inc", cat: "Sensitive Files", desc: "Include file (.inc)", regex: "\\.inc(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-java", cat: "Sensitive Files", desc: "Java source (.java)", regex: "\\.java(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-jks", cat: "Sensitive Files", desc: "Java KeyStore (.jks)", regex: "\\.jks(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-kwallet", cat: "Sensitive Files", desc: "KDE Wallet (.kwallet)", regex: "\\.kwallet(?:[?#]|$)", sections: ["req_url"], severity: "critical" },
  { id: "file-xpl", cat: "Sensitive Files", desc: "Exploit file (.xpl)", regex: "\\.xpl(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-log", cat: "Sensitive Files", desc: "Log file (.log)", regex: "\\.log(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-tpm", cat: "Sensitive Files", desc: "TPM key (.tpm)", regex: "\\.tpm(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-bek", cat: "Sensitive Files", desc: "BitLocker key (.bek)", regex: "\\.bek(?:[?#]|$)", sections: ["req_url"], severity: "critical" },
  { id: "file-mdf", cat: "Sensitive Files", desc: "Database (.mdf)", regex: "\\.mdf(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-sdf", cat: "Sensitive Files", desc: "Database (.sdf)", regex: "\\.sdf(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-pcap", cat: "Sensitive Files", desc: "Packet capture (.pcap)", regex: "\\.pcap(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-old", cat: "Sensitive Files", desc: "Old backup (.old)", regex: "\\.old(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-ovpn", cat: "Sensitive Files", desc: "OpenVPN config (.ovpn)", regex: "\\.ovpn(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-pdf", cat: "Sensitive Files", desc: "Document (.pdf)", regex: "\\.pdf(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-php", cat: "Sensitive Files", desc: "PHP source (.php)", regex: "\\.php(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-psafe3", cat: "Sensitive Files", desc: "Password Safe (.psafe3)", regex: "\\.psafe3(?:[?#]|$)", sections: ["req_url"], severity: "critical" },
  { id: "file-yml", cat: "Sensitive Files", desc: "YAML config (.yml)", regex: "\\.yml(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-pkcs12", cat: "Sensitive Files", desc: "Certificate (.pkcs12)", regex: "\\.pkcs12(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-p12", cat: "Sensitive Files", desc: "Certificate (.p12)", regex: "\\.p12(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-pfx", cat: "Sensitive Files", desc: "Certificate (.pfx)", regex: "\\.pfx(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-pkr", cat: "Sensitive Files", desc: "PGP public keyring (.pkr)", regex: "\\.pkr(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-skr", cat: "Sensitive Files", desc: "PGP secret keyring (.skr)", regex: "\\.skr(?:[?#]|$)", sections: ["req_url"], severity: "critical" },
  { id: "file-asc", cat: "Sensitive Files", desc: "PGP armored key (.asc)", regex: "\\.asc(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-pem", cat: "Sensitive Files", desc: "PEM key/cert (.pem)", regex: "\\.pem(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-private-key", cat: "Sensitive Files", desc: "Private key (.private_key)", regex: "\\.private_key(?:[?#]|$)", sections: ["req_url"], severity: "critical" },
  { id: "file-pptx", cat: "Sensitive Files", desc: "Presentation (.pptx)", regex: "\\.pptx(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-ppt", cat: "Sensitive Files", desc: "Presentation (.ppt)", regex: "\\.ppt(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-py", cat: "Sensitive Files", desc: "Python source (.py)", regex: "\\.py(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-rdp", cat: "Sensitive Files", desc: "Remote Desktop (.rdp)", regex: "\\.rdp(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-rb", cat: "Sensitive Files", desc: "Ruby source (.rb)", regex: "\\.rb(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-sqlite", cat: "Sensitive Files", desc: "SQLite database (.sqlite)", regex: "\\.sqlite(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-sqlite3", cat: "Sensitive Files", desc: "SQLite database (.sqlite3)", regex: "\\.sqlite3(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-plist", cat: "Sensitive Files", desc: "Property list (.plist)", regex: "\\.plist(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-exports", cat: "Sensitive Files", desc: "NFS exports (.exports)", regex: "\\.exports(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-functions", cat: "Sensitive Files", desc: "Shell functions (.functions)", regex: "\\.functions(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-extra", cat: "Sensitive Files", desc: "Extra config (.extra)", regex: "\\.extra(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-tmp", cat: "Sensitive Files", desc: "Temp file (.tmp)", regex: "\\.tmp(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "file-terraform-tfvars", cat: "Sensitive Files", desc: "Terraform variables (terraform.tfvars)", regex: "terraform\\.tfvars(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-txt", cat: "Sensitive Files", desc: "Text file (.txt)", regex: "\\.txt(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "file-tblk", cat: "Sensitive Files", desc: "Tunnelblick VPN (.tblk)", regex: "\\.tblk(?:[?#]|$)", sections: ["req_url"], severity: "high" },
  { id: "file-fve", cat: "Sensitive Files", desc: "BitLocker metadata (.fve)", regex: "\\.fve(?:[?#]|$)", sections: ["req_url"], severity: "critical" },
  { id: "file-xml", cat: "Sensitive Files", desc: "XML file (.xml)", regex: "\\.xml(?:[?#]|$)", sections: ["req_url"], severity: "low" },

  // ═══════════════════════════════════════════════════════════════
  //  Passive Scanner — Stack Traces & Errors
  // ═══════════════════════════════════════════════════════════════
  { id: "stacktrace-java", cat: "Error Disclosure", desc: "Java Stack Trace", regex: "at\\s+[a-zA-Z0-9$_.]+\\([A-Za-z0-9_]+\\.java:\\d+\\)", sections: ["resp_body"], severity: "high" },
  { id: "stacktrace-python", cat: "Error Disclosure", desc: "Python Traceback", regex: "Traceback \\(most recent call last\\)", sections: ["resp_body"], severity: "high" },
  { id: "stacktrace-python-file", cat: "Error Disclosure", desc: "Python File Reference", regex: "File \"[^\"]+\\.py\", line \\d+", sections: ["resp_body"], severity: "high" },
  { id: "stacktrace-dotnet", cat: "Error Disclosure", desc: ".NET Stack Trace", regex: "at\\s+[A-Za-z0-9_.]+\\.[A-Za-z0-9_]+\\([^)]*\\)\\s+in\\s+[A-Za-z]:", sections: ["resp_body"], severity: "high" },
  { id: "stacktrace-php", cat: "Error Disclosure", desc: "PHP Error/Stack Trace", regex: "(?:Fatal error|Warning|Notice|Parse error):.+in\\s+/[^\\s]+\\.php(?:\\s+on line\\s+\\d+)?", sections: ["resp_body"], severity: "high" },
  { id: "stacktrace-ruby", cat: "Error Disclosure", desc: "Ruby Stack Trace", regex: "/[^\\s]+\\.rb:\\d+:in\\s+`", sections: ["resp_body"], severity: "high" },
  { id: "stacktrace-node", cat: "Error Disclosure", desc: "Node.js Stack Trace", regex: "at\\s+(?:Object\\.|Module\\.|Function\\.)?[\\w.]+\\s+\\(/[^)]+\\.js:\\d+:\\d+\\)", sections: ["resp_body"], severity: "high" },
  { id: "stacktrace-go", cat: "Error Disclosure", desc: "Go Panic/Stack", regex: "goroutine\\s+\\d+\\s+\\[", sections: ["resp_body"], severity: "high" },
  { id: "sql-error", cat: "Error Disclosure", desc: "SQL Error Message", regex: "(?:ORA-\\d{4,5}|mysql_fetch|pg_query|SQLite3::|SQLSTATE\\[|Unclosed quotation mark|syntax error.{0,30}SQL|You have an error in your SQL syntax)", sections: ["resp_body"], severity: "high" },
  { id: "asp-error", cat: "Error Disclosure", desc: "ASP.NET Error", regex: "(?:Server Error in|Description: An unhandled exception|Stack Trace:|\\[SqlException|\\[NullReferenceException)", sections: ["resp_body"], severity: "high" },
  { id: "debug-page", cat: "Error Disclosure", desc: "Debug/Error Page", regex: "(?:DJANGO DEBUG|Debug Mode|Whoops!|Symfony\\s+Exception|Laravel)", sections: ["resp_body"], severity: "high" },
  { id: "verbose-error-msg", cat: "Error Disclosure", desc: "Verbose Error Message", regex: "(?:Exception in thread|caused by:|root cause:|internal server error.{0,40}stack)", sections: ["resp_body"], severity: "medium" },

  // ═══════════════════════════════════════════════════════════════
  //  Passive Scanner — Security Headers & CORS
  // ═══════════════════════════════════════════════════════════════
  { id: "cors-wildcard", cat: "Security Misconfiguration", desc: "CORS Wildcard Origin", regex: "access-control-allow-origin:\\s*\\*", sections: ["resp_headers"], severity: "medium" },
  { id: "cors-credentials-wild", cat: "Security Misconfiguration", desc: "CORS Credentials with Wildcard", regex: "access-control-allow-credentials:\\s*true", sections: ["resp_headers"], severity: "high" },
  { id: "x-debug-header", cat: "Security Misconfiguration", desc: "Debug Header Exposed", regex: "x-debug(?:-token)?:", sections: ["resp_headers"], severity: "medium" },
  { id: "x-powered-by", cat: "Information Disclosure", desc: "X-Powered-By Header", regex: "x-powered-by:", sections: ["resp_headers"], severity: "low" },
  { id: "server-version", cat: "Information Disclosure", desc: "Server Version Disclosure", regex: "server:\\s*(?:apache|nginx|iis|tomcat|jetty|gunicorn|openresty)/[\\d.]+", sections: ["resp_headers"], severity: "low" },
  { id: "x-aspnet-version", cat: "Information Disclosure", desc: "ASP.NET Version Header", regex: "x-aspnet-version:", sections: ["resp_headers"], severity: "medium" },
  { id: "x-runtime", cat: "Information Disclosure", desc: "X-Runtime Header (timing)", regex: "x-runtime:", sections: ["resp_headers"], severity: "low" },

  // ═══════════════════════════════════════════════════════════════
  //  Passive Scanner — Open Redirect & Injection Indicators
  // ═══════════════════════════════════════════════════════════════
  { id: "open-redirect-param", cat: "Open Redirect", desc: "Redirect Parameter in URL", regex: "[?&](?:redirect|return|next|url|dest|destination|rurl|redir|forward|goto|target|link|continue|returnUrl|returnTo|redirect_uri|callback|out)=https?://", sections: ["req_url"], severity: "medium" },
  { id: "location-redirect", cat: "Open Redirect", desc: "Location Header Redirect", regex: "location:\\s*https?://(?!(?:localhost|127\\.0\\.0\\.1))", sections: ["resp_headers"], severity: "low" },
  { id: "html-form-action-ext", cat: "Open Redirect", desc: "Form Action to External URL", regex: "action\\s*=\\s*[\"']https?://", sections: ["resp_body"], severity: "low" },

  // ═══════════════════════════════════════════════════════════════
  //  Passive Scanner — Information Disclosure
  // ═══════════════════════════════════════════════════════════════
  { id: "dir-listing", cat: "Information Disclosure", desc: "Directory Listing", regex: "(?:Index of /|\\[To Parent Directory\\]|<title>Directory listing for)", sections: ["resp_body"], severity: "high" },
  // ── Source maps ────────────────────────────────────────────────────────────
  // A .map file hands over the original, un-minified sources (and with
  // sourcesContent, the full file bodies). Ordered narrow → broad; the
  // reference rule excludes data: URIs so an inline map is reported once, by
  // the inline rule, rather than twice.
  { id: "source-map-ref", cat: "Information Disclosure", desc: "Source Map Reference", regex: "//[#@]\\s*sourceMappingURL\\s*=\\s*(?!data:)[^\\s*'\"]+", sections: ["resp_body"], severity: "low" },
  { id: "source-map-inline", cat: "Information Disclosure", desc: "Inline (data: URI) Source Map", regex: "//[#@]\\s*sourceMappingURL\\s*=\\s*data:[^\\s,]{0,120},", sections: ["resp_body"], severity: "medium" },
  { id: "source-url-ref", cat: "Information Disclosure", desc: "sourceURL Directive", regex: "//[#@]\\s*sourceURL\\s*=\\s*[^\\s*'\"]+", sections: ["resp_body"], severity: "low" },
  { id: "source-map-file", cat: "Information Disclosure", desc: "Source Map File Requested (.map)", regex: "\\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|less)\\.map(?:[?#]|$)", sections: ["req_url"], severity: "medium" },
  { id: "source-map-file-other", cat: "Information Disclosure", desc: "Map File Requested (.map)", regex: "(?<!\\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|less))\\.map(?:[?#]|$)", sections: ["req_url"], severity: "low" },
  { id: "source-map-header", cat: "Information Disclosure", desc: "SourceMap Response Header", regex: "^(?:x-)?sourcemap:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  // The map document itself came back — this is the original source code, not a pointer to it
  { id: "source-map-body", cat: "Information Disclosure", desc: "Source Map Body Served (original sources exposed)", regex: "\"sourcesContent\"\\s*:\\s*\\[", sections: ["resp_body"], severity: "high" },
  // Only when sourcesContent is absent, so a map carrying the full sources is
  // reported once (as high) instead of twice. The lookahead sits after the
  // anchor text so it runs only where the prefix already matched, and v3 emits
  // sourcesContent after sources, so looking forward is enough.
  { id: "source-map-body-v3", cat: "Information Disclosure", desc: "Source Map Document (v3, no embedded sources)", regex: "\"version\"\\s*:\\s*3\\s*,\\s*\"(?:file|sources|sourceRoot|mappings)\"(?![\\s\\S]*\"sourcesContent\")", sections: ["resp_body"], severity: "medium" },
  { id: "html-comment-todo", cat: "Information Disclosure", desc: "HTML Comment (TODO/FIXME/HACK/BUG)", regex: "<!--[^>]*(?:TODO|FIXME|HACK|BUG|XXX|TEMP|DEBUG)[^>]*-->", sections: ["resp_body"], severity: "low" },
  { id: "html-comment-creds", cat: "Information Disclosure", desc: "HTML Comment with Credentials Hint", regex: "<!--[^>]*(?:password|passwd|secret|credential|api.?key|token)[^>]*-->", sections: ["resp_body"], severity: "medium" },
  { id: "phpinfo-page", cat: "Information Disclosure", desc: "phpinfo() Page", regex: "<title>phpinfo\\(\\)</title>", sections: ["resp_body"], severity: "critical" },
  { id: "wp-config-exposed", cat: "Information Disclosure", desc: "WordPress Config Exposed", regex: "define\\s*\\(\\s*['\"]DB_PASSWORD['\"]", sections: ["resp_body"], severity: "critical" },
  { id: "git-config-exposed", cat: "Information Disclosure", desc: ".git/config Exposed", regex: "\\[core\\]\\s*\\n\\s*repositoryformatversion", sections: ["resp_body"], severity: "critical" },
  { id: "env-file-exposed", cat: "Information Disclosure", desc: ".env File Exposed", regex: "(?:DB_PASSWORD|APP_KEY|SECRET_KEY|API_SECRET)\\s*=\\s*\\S+", sections: ["resp_body"], severity: "critical" },

  // ═══════════════════════════════════════════════════════════════
  //  Passive Scanner — PII & Sensitive Data
  // ═══════════════════════════════════════════════════════════════
  { id: "ssn-us", cat: "PII", desc: "US Social Security Number", regex: "\\b\\d{3}-\\d{2}-\\d{4}\\b", sections: ["resp_body"], severity: "critical" },
  { id: "credit-card-visa", cat: "PII", desc: "Credit Card (Visa)", regex: "\\b4\\d{3}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b", sections: ["resp_body"], severity: "critical" },
  { id: "credit-card-mc", cat: "PII", desc: "Credit Card (Mastercard)", regex: "\\b5[1-5]\\d{2}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b", sections: ["resp_body"], severity: "critical" },
  { id: "credit-card-amex", cat: "PII", desc: "Credit Card (Amex)", regex: "\\b3[47]\\d{2}[\\s-]?\\d{6}[\\s-]?\\d{5}\\b", sections: ["resp_body"], severity: "critical" },
  { id: "phone-intl", cat: "PII", desc: "Phone Number (International)", regex: "\\+\\d{1,3}[\\s.-]?\\(?\\d{2,4}\\)?[\\s.-]?\\d{3,4}[\\s.-]?\\d{3,4}", sections: ["resp_body"], severity: "medium" },
  { id: "jwt-in-response", cat: "PII", desc: "JWT Token in Response", regex: "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", sections: ["resp_body"], severity: "high" },
  { id: "bcrypt-hash", cat: "PII", desc: "Bcrypt Hash", regex: "\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}", sections: ["resp_body"], severity: "high" },
  { id: "md5-hash-context", cat: "PII", desc: "MD5 Hash in Context", regex: "(?:password|hash|digest|md5)[\"':=\\s]+[a-f0-9]{32}(?![a-f0-9])", sections: ["resp_body"], severity: "medium" },

  // ═══════════════════════════════════════════════════════════════
  //  Tech & Version Disclosure (response headers)
  // ═══════════════════════════════════════════════════════════════
  // These run against the joined "Name: value" header text, so every pattern is
  // anchored on the header name and bounded with [^\n] — linear time, no
  // backtracking blowup on long header values.
  // A version number is worth more than a bare product name (it maps straight to
  // a CVE lookup), so version-bearing patterns are "medium" and the rest "low".

  // Server / product banners carrying a version
  { id: "hdr-server-version", cat: "Tech & Version Disclosure", desc: "Server header leaks version", regex: "^server:[^\\n]*?\\d+\\.\\d+[^\\n]*", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-server", cat: "Tech & Version Disclosure", desc: "Server header leaks product", regex: "^server:(?![^\\n]*\\d+\\.\\d+)[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-x-powered-by", cat: "Tech & Version Disclosure", desc: "X-Powered-By", regex: "^x-powered-by:(?![^\\n]*\\d+\\.\\d+)[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-x-powered-by-version", cat: "Tech & Version Disclosure", desc: "X-Powered-By leaks version", regex: "^x-powered-by:[^\\n]*?\\d+\\.\\d+[^\\n]*", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-via", cat: "Tech & Version Disclosure", desc: "Via header (proxy/cache chain)", regex: "^via:[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },

  // Framework / runtime versions
  { id: "hdr-aspnet-version", cat: "Tech & Version Disclosure", desc: "ASP.NET version", regex: "^x-aspnet-version:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-aspnetmvc-version", cat: "Tech & Version Disclosure", desc: "ASP.NET MVC version", regex: "^x-aspnetmvc-version:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-php-version", cat: "Tech & Version Disclosure", desc: "PHP version", regex: "^x-php-version:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-rails-runtime", cat: "Tech & Version Disclosure", desc: "X-Runtime (Ruby on Rails)", regex: "^x-runtime:[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-generator", cat: "Tech & Version Disclosure", desc: "X-Generator (CMS/product)", regex: "^x-generator:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-app-version", cat: "Tech & Version Disclosure", desc: "Application version header", regex: "^x-(?:app(?:lication)?|api|build|release|service)-version:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-version-generic", cat: "Tech & Version Disclosure", desc: "Generic X-Version header", regex: "^x-version:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },

  // CMS / platform fingerprints
  { id: "hdr-drupal", cat: "Tech & Version Disclosure", desc: "Drupal header", regex: "^x-drupal-[a-z-]+:[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-wordpress", cat: "Tech & Version Disclosure", desc: "WordPress header", regex: "^x-(?:wp-[a-z-]+|wordpress-[a-z-]+|redirect-by|pingback):[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-sharepoint", cat: "Tech & Version Disclosure", desc: "SharePoint version", regex: "^microsoftsharepointteamservices:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-owa", cat: "Tech & Version Disclosure", desc: "Exchange/OWA version", regex: "^x-owa-version:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-atlassian", cat: "Tech & Version Disclosure", desc: "Atlassian product header", regex: "^x-(?:confluence-[a-z-]+|ausername|arequestid|jira-[a-z-]+):[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-jenkins", cat: "Tech & Version Disclosure", desc: "Jenkins version", regex: "^x-jenkins(?:-[a-z-]+)?:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-liferay", cat: "Tech & Version Disclosure", desc: "Liferay Portal header", regex: "^liferay-portal:[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-shopify", cat: "Tech & Version Disclosure", desc: "Shopify stage header", regex: "^x-shopify-[a-z-]+:[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },

  // App servers / gateways / proxies
  { id: "hdr-kong", cat: "Tech & Version Disclosure", desc: "Kong API gateway", regex: "^x-kong-[a-z-]+:[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-envoy", cat: "Tech & Version Disclosure", desc: "Envoy proxy header", regex: "^x-envoy-[a-z-]+:[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-varnish", cat: "Tech & Version Disclosure", desc: "Varnish cache header", regex: "^x-varnish:[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-litespeed", cat: "Tech & Version Disclosure", desc: "LiteSpeed header", regex: "^x-(?:litespeed-[a-z-]+|lsadc|turbo-charged-by):[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },
  { id: "hdr-pagespeed", cat: "Tech & Version Disclosure", desc: "PageSpeed module version", regex: "^x-(?:mod-pagespeed|page-speed):[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-rack-cache", cat: "Tech & Version Disclosure", desc: "Rack cache header", regex: "^x-rack-cache:[^\\n]+", sections: ["resp_headers"], severity: "low", flags: "gim" },

  // Internal infrastructure leaks — these expose hostnames, not just products
  { id: "hdr-backend-server", cat: "Tech & Version Disclosure", desc: "Internal backend hostname", regex: "^x-(?:backend|backend-server|server|node|host|served-by|application-context|powered-by-plesk):[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
  { id: "hdr-upstream", cat: "Tech & Version Disclosure", desc: "Upstream/origin server header", regex: "^x-(?:upstream[a-z-]*|origin-server|proxy-backend):[^\\n]+", sections: ["resp_headers"], severity: "medium", flags: "gim" },
];
