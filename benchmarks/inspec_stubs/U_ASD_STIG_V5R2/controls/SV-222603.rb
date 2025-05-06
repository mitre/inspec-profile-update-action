control 'SV-222603' do
  title 'The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities.'
  desc 'Cross-Site Request Forgery (CSRF) is an attack where a website user is forced to execute an unwanted action on a website that he or she is currently authenticated to. An attacker, through social engineering (e.g., e-mail or chat) creates a hyperlink which executes unwanted actions on the website the victim is authenticated to and sends it to the victim. If the victim clicks on the link, the action is executed unbeknownst to the victim.

A CSRF attack executes a website request on behalf of the user which can lead to a compromise of the user’s data. What is needed to be successful is for the attacker to know the URL, an authenticated application user, and trick the user into clicking the malicious link.

While XSS is not needed for a CSRF attack to work, XSS vulnerabilities can provide the attacker with a vector to obtain information from the user that may be used in mitigating the risk. The application must not be vulnerable to XSS as an XSS attack can be used to help defeat token, double-submit cookie, referrer and origin-based CSRF defenses.'
  desc 'check', 'Review the application documentation, the code review reports and the vulnerability assessment scan results from the automated vulnerability assessment tools.

Verify scan configuration settings include web-based application settings which include XSS tests.

Review the scan results for CSRF vulnerabilities.

If the scan results indicate aspects of the application are vulnerable to CSRF, request subsequent scan data that shows the CSRF vulnerabilities previously detected have been fixed.

If results that show compliance are not available, request proof of any steps that have been taken to mitigate the risk.

Mitigation steps include using web reputation filters to identify sources of exploits delivered via CSRF, web application firewalls that validate cookie and the referrer field in the HTTP headers, or product specific IPS filters that identify and intercept known CSRF vulnerabilities in web-based applications.

If scan results are not available ask the application administrator to provide evidence that shows the application is designed to address CSRF security issues. There are various methods for mitigating the risk, including using a challenge token that is tied to the users session.

If application scan results show an unremediated CSRF vulnerability, or if no scan results are available, or no mitigations have been enabled, this is a finding.'
  desc 'fix', 'Configure the application to use unpredictable challenge tokens and check the HTTP referrer to ensure the request was issued from the site itself.  Implement mitigating controls as required such as using web reputation services.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24273r493717_chk'
  tag severity: 'medium'
  tag gid: 'V-222603'
  tag rid: 'SV-222603r508029_rule'
  tag stig_id: 'APSC-DV-002500'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-24262r493718_fix'
  tag 'documentable'
  tag legacy: ['SV-84881', 'V-70259']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
