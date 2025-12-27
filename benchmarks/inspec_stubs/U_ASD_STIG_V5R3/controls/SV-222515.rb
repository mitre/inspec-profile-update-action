control 'SV-222515' do
  title 'An application vulnerability assessment must be conducted.'
  desc 'An application vulnerability assessment is a test conducted in order to identify weaknesses and security vulnerabilities that may exist within an application.  The testing must cover all aspects and components of the application architecture.  If an application consists of a web server and a database, then both components must be tested for vulnerabilities to the fullest extent possible.

Vulnerability assessment tests normally utilize a combination of specialized software called application vulnerability scanners as well as custom scripts and manual tests.  In some instances, multiple tools are required in order to test all aspects of application features, functions and architecture.  The vulnerability scanner is typically configured to communicate with the application through the user interface or via an applications communication port.  In addition to using automated tools, manual tests conducted from the OS console such as executing custom scripts or reviewing configuration settings for known vulnerabilities may also be included as part of the test.

Testers will typically utilize application user test accounts in order to test application features and functionality such as adding content, executing queries and completing transactions. The vulnerability testing software utilizes user actions and access as well as a list of known security vulnerabilities in order to detect and identify weak security controls or misconfigurations that could potentially be manipulated by the user or create a security vulnerability.

The Open Web Application Security Project (OWASP) top 10 for 2013 includes the following top issues that should be tested.  The site is available by pointing your browser to https://www.owasp.org. 

A1 Injection
A2 Weak authentication and session management
A3 XSS
A4 Insecure Direct Object References
A5 Security Misconfiguration
A6 Sensitive Data Exposure
A7 Missing Function Level Access Control
A8 Cross Site Request Forgery
A9 Using Components with Known Vulnerabilities
A10 Unvalidated Redirects and Forwards

The OWASP top 10 are categories of tests that can be applied to most but not necessarily all applications and are provided as an example of what to test for.  Scanning tools include a multitude of tests that fall under these categories but may refer to these tests by a different name.

Testing must be conducted on a periodic basis while the application is in production and subsequent to system changes to ensure any changes made to the system do not introduce new security vulnerabilities.'
  desc 'check', 'Review the application documentation to understand application architecture.

Interview the application administrator, obtain and review their application vulnerability scanning process.

Request the latest scan results including scan configuration settings.

Review scan configurations and ensure coverage of all application architecture has been tested.  The proper scanning tool or combination of tools must be utilized in order to ensure the full range of application features and functionality is tested. 

For example, if the application includes a web interface and a SQL database, then ensure test results for web and SQL vulnerabilities are provided.  Although web and SQL applications are included as examples and are the prevalent types of applications, this requirement is not intended to be limited to just the aforementioned application architectures.   Ensure test results are provided from all testing tools employed during vulnerability testing.

If high risk security vulnerabilities are identified in the scan results, request subsequent test results that indicate the issues have been fixed or mitigated.

If the high risk issues identified in the report have not been fixed or mitigated to a level accepted by the ISSO and the ISSM, or if the application administrator cannot produce vulnerability security testing results that cover the range of application functionality, this is a finding.'
  desc 'fix', 'Configure the application vulnerability scanners to test all components of the application, conduct vulnerability scans on a regular basis and remediate identified issues.  Retain scan results for compliance verification.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24185r493453_chk'
  tag severity: 'medium'
  tag gid: 'V-222515'
  tag rid: 'SV-222515r879887_rule'
  tag stig_id: 'APSC-DV-001460'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24174r493454_fix'
  tag 'documentable'
  tag legacy: ['SV-84135', 'V-69513']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
