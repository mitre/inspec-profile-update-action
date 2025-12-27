control 'SV-214446' do
  title 'A private IIS 8.5 website must only accept Secure Socket Layer connections.'
  desc 'Transport Layer Security (TLS) encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2-approved TLS version, and all non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Note: If the server being reviewed is a public IIS 8.5 web server, this is Not Applicable.
Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.
Note: If the server being reviewed is hosting WSUS, this is Not Applicable.
Note: If SSL is installed on load balancer/proxy server through which traffic is routed to the IIS 8.5 server, and the IIS 8.5 server receives traffic from the load balancer/proxy server, the SSL requirement must be met on the load balancer/proxy server.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.
Click the site name.
Double-click the "SSL Settings" icon.
Verify "Require SSL" check box is selected.

If the "Require SSL" check box is not selected, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.
Click the site name.
Double-click the "SSL Settings" icon.
Select "Require SSL" check box.
Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15655r903079_chk'
  tag severity: 'medium'
  tag gid: 'V-214446'
  tag rid: 'SV-214446r903081_rule'
  tag stig_id: 'IISW-SI-000203'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-15653r903080_fix'
  tag 'documentable'
  tag legacy: ['SV-91475', 'V-76779']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
