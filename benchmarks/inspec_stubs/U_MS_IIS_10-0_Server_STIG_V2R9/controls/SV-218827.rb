control 'SV-218827' do
  title 'The IIS 10.0 web server must enable HTTP Strict Transport Security (HSTS).'
  desc 'HTTP Strict Transport Security (HSTS) ensures browsers always connect to a website over TLS. HSTS exists to remove the need for redirection configurations. HSTS relies on the browser, web server, and a public "Allowlist". If the browser does not support HSTS, it will be ignored.'
  desc 'check', 'Access the IIS 10.0 Web Server.
Open IIS Manager.
Click the IIS 10.0 web server name.
Open on Configuration Editor under Management.
For the Section, navigate to system.applicationHost/sites.
Expand siteDefaults and HSTS.
If enabled is not set to True, this is a finding.
If includeSubDomains is not set to True, this is a finding.
If max-age is not set to a value greater than 0, this is a finding.
If redirectHttpToHttps is not True, this is a finding.

If the website is behind a load balancer or proxy server, and HSTS enablement is handled there, this is Not Applicable.

If the version of Windows Server does not natively support HSTS, this is not a finding.'
  desc 'fix', 'Using the Configuration Editor in the IIS Manager or Powershell:
Enable HSTS.
Set includeSubDomains to True.
Set max-age to a value greater than 0.
Set redirectHttpToHttps to True.'
  impact 0.3
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20299r810854_chk'
  tag severity: 'low'
  tag gid: 'V-218827'
  tag rid: 'SV-218827r879887_rule'
  tag stig_id: 'IIST-SV-000205'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20297r802885_fix'
  tag 'documentable'
  tag legacy: ['SV-109293', 'V-100189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
