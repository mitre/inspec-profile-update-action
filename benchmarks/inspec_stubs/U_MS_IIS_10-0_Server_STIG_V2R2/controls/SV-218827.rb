control 'SV-218827' do
  title 'The IIS 10.0 web server must enable HTTP Strict Transport Security (HSTS).'
  desc 'HTTP Strict Transport Security (HSTS) ensures browsers always connect to a website over TLS. HSTS exists to remove the need for redirection configurations. HSTS relies on the browser, web server, and a public "Allowlist". If the browser does not support HSTS, it will be ignored.'
  desc 'check', 'Access the IIS 10.0 Web Server.

Open IIS Manager.

Click the IIS 10.0 web server name.

Click on HSTS.

Verify “Enable” is checked, and Max-Age is set to something other than “0”.

Verify “IncludeSubDomains” and “Redirect HTTP to HTTPS” are checked.

Click "OK".

If HSTS has not been enabled, this is a finding.

If the website is behind a load balancer or proxy server, and HSTS enablement is handled there, this is Not Applicable.

The recommended max age is 8 minutes (480 seconds) or greater. Any value greater than 0 is not a finding.

If the version of Windows Server does not natively support HSTS, this is not a finding.'
  desc 'fix', 'Enable HSTS via IIS Manager or Powershell.'
  impact 0.3
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20299r695269_chk'
  tag severity: 'low'
  tag gid: 'V-218827'
  tag rid: 'SV-218827r695271_rule'
  tag stig_id: 'IIST-SV-000205'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20297r695270_fix'
  tag 'documentable'
  tag legacy: ['SV-109293', 'V-100189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
