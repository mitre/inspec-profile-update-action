control 'SV-218768' do
  title 'The IIS 10.0 private website must employ cryptographic mechanisms (TLS) and require client certificates.'
  desc 'TLS encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2-approved TLS version, and all non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Note: If SSL is installed on load balancer/proxy server through which traffic is routed to the IIS 10.0 server, and the IIS 10.0 server receives traffic from the load balancer/proxy server, the SSL requirement must be met on the load balancer/proxy server. In this case, this requirement is Not Applicable.
Note: If this is a public-facing web server, this requirement is Not Applicable.
Note: If this server is hosting WSUS, this requirement is Not Applicable.
Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Double-click the "SSL Settings" icon under the "IIS" section.

Verify "Require SSL" is checked.

Verify "Client Certificates Required" is selected.

Click the site under review.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.webServer/security/access".

The value for "sslFlags" set must include "ssl128".

If the "Require SSL" is not selected, this is a finding.
If the "Client Certificates Required" is not selected, this is a finding.
If the "sslFlags" is not set to "ssl128", this is a finding.'
  desc 'fix', 'Note: If SSL is installed on load balancer/proxy server through which traffic is routed to the IIS 10.0 server, and the IIS 10.0 server receives traffic from the load balancer/proxy server, the SSL requirement must be met on the load balancer/proxy server. In this case, this requirement is Not Applicable.
Note: If this is a public-facing web server, this requirement is Not Applicable.
Note: If this server is hosting WSUS, this requirement is Not Applicable.
Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Double-click the "SSL Settings" icon under the "IIS" section.

Select the "Require SSL" setting.

Select the "Client Certificates Required" setting.

Click "Apply" in the "Actions" pane.

Click the site under review.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.webServer/security/access".

Click on the drop-down list for "sslFlags".

Select the "Ssl128" check box.

Click "Apply" in the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20241r863022_chk'
  tag severity: 'medium'
  tag gid: 'V-218768'
  tag rid: 'SV-218768r879800_rule'
  tag stig_id: 'IIST-SI-000242'
  tag gtitle: 'SRG-APP-000429-WSR-000113'
  tag fix_id: 'F-20239r863023_fix'
  tag 'documentable'
  tag legacy: ['SV-109361', 'V-100257']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
