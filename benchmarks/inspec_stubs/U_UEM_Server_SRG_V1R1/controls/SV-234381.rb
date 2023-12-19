control 'SV-234381' do
  title 'The UEM server must map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis. 

'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server maps the authenticated identity to the individual user or group account for PKI-based authentication.

If the UEM server does not map the authenticated identity to the individual user or group account for PKI-based authentication, this is a finding.'
  desc 'fix', 'Configure the UEM server to map the authenticated identity to the individual user or group account for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37566r614153_chk'
  tag severity: 'medium'
  tag gid: 'V-234381'
  tag rid: 'SV-234381r617409_rule'
  tag stig_id: 'SRG-APP-000177-UEM-000108'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-37531r614154_fix'
  tag satisfies: ['FIA \nReference:PP-MDM-414003']
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
