control 'SV-214460' do
  title 'A private websites authentication mechanism must use client certificates to transmit session identifier to assure integrity.'
  desc 'A DoD private website must utilize PKI as an authentication mechanism for web users. Information systems residing behind web servers requiring authorization based on individual identity must use the identity provided by certificate-based authentication to support access control decisions. Not using client certificates allows an attacker unauthenticated access to private websites.

'
  desc 'check', 'Note: If the server being reviewed is a public IIS 8.5 web server, this is Not Applicable.
Note: If the server is hosting Exchange, this is Not Applicable.
Note: If certificate handling is performed at the Proxy/Load Balancer, this is not a finding.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.
Double-click the "SSL Settings" icon.
Verify the "Clients Certificate Required" check box is selected.

If the "Clients Certificate Required" check box is not selected, this is a finding.'
  desc 'fix', 'Note: If the server being reviewed is a public IIS 8.5 web server, this is Not Applicable.
Note: If the server is hosting Exchange, this is Not Applicable.
Note: If certificate handling is performed at the Proxy/Load Balancer, this is not a finding.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.
Double-click the "SSL Settings" icon.
Verify the "Clients Certificate Required" check box is selected.
Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15669r802878_chk'
  tag severity: 'medium'
  tag gid: 'V-214460'
  tag rid: 'SV-214460r802880_rule'
  tag stig_id: 'IISW-SI-000220'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag fix_id: 'F-15667r802879_fix'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000224-WSR-000135', 'SRG-APP-000427-WSR-000186']
  tag 'documentable'
  tag legacy: ['SV-91505', 'V-76809']
  tag cci: ['CCI-000197', 'CCI-001188', 'CCI-002470']
  tag nist: ['IA-5 (1) (c)', 'SC-23 (3)', 'SC-23 (5)']
end
