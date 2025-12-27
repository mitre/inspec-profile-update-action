control 'SV-222576' do
  title 'The application must set the secure flag on session cookies.'
  desc 'Many web development frameworks such as PHP, .NET, ASP as well as application servers include their own mechanisms for session management. Whenever possible it is recommended to utilize the provided session management framework.

Setting the secure bit on session cookie ensures the session cookie is only sent via TLS/SSL HTTPS connections.  This helps to ensure confidentiality as the session cookie is not able to be viewed by unauthorized parties as it transits the network.

Setting the secure flag on all cookies may also be warranted depending upon application design but at a minimum, the session cookie must always be secured.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify when session cookies are created.

If vulnerability scan results are available, reference the most recent vulnerability scan results.

Verify that the scan configuration includes checks for the secure flag on session cookies.  If scan configuration settings are not available, follow the manual procedure provided below.

Review the scan results and determine if the secure flag not being set was identified as a vulnerability.

To manually perform the check, open a web browser, logon to the web application and use the web browser to view the new session cookie.  

The procedures used for viewing and clearing browser cookies will vary based upon the web browser used.  Providing steps for every browser is outside the scope of the STIG.  There are numerous sites that document how to view cookies using various web browsers.

For IE11:
Alt-X >> Internet options >> General >> Settings >> View Files

A windows explorer box will open that contains the contents of the Temporary Internet Files.  Browse the folder and locate the application session cookie(s).  View the contents of the cookie(s).

If the "secure" flag is not set on the session cookie, or if the vulnerability scan results indicate the application does not set the secure flag on cookies, this is a finding.'
  desc 'fix', 'Configure the application to ensure the secure flag is set on session cookies.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24246r493636_chk'
  tag severity: 'medium'
  tag gid: 'V-222576'
  tag rid: 'SV-222576r508029_rule'
  tag stig_id: 'APSC-DV-002220'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-24235r493637_fix'
  tag 'documentable'
  tag legacy: ['SV-84825', 'V-70203']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
