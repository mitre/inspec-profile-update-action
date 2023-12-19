control 'SV-218738' do
  title 'A public IIS 10.0 website must only accept Secure Socket Layer (SSL) connections when authentication is required.'
  desc 'Transport Layer Security (TLS) encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2-approved TLS version, and all non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Note: If the server being reviewed is a private IIS 10.0 web server, this is Not Applicable.
Note: If the server being reviewed is a public IIS 10.0 web server not requiring authentication, this is Not Applicable.
Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.
Note: If the server being reviewed is hosting WSUS, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Double-click the "SSL Settings" icon.

Verify "Require SSL" check box is selected.

If the "Require SSL" check box is not selected, this is a finding.'
  desc 'fix', 'Note: If the server being reviewed is a private IIS 10.0 web server, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Double-click the "SSL Settings" icon.

Select "Require SSL" check box.

Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20211r903110_chk'
  tag severity: 'medium'
  tag gid: 'V-218738'
  tag rid: 'SV-218738r903111_rule'
  tag stig_id: 'IIST-SI-000204'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-20209r505266_fix'
  tag 'documentable'
  tag legacy: ['SV-109301', 'V-100197']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
