control 'SV-207234' do
  title 'The VPN Gateway must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

This requirement only applies to components where this is specific to the function of the device (e.g., IDPS sensor logs, firewall logs). This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the VPN Gateway off-loads log records onto a different system or media than the system being audited.

If the VPN Gateway does not off-load audit records onto a different system or media than the system being audited, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to off-load audit records onto a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7494r378323_chk'
  tag severity: 'medium'
  tag gid: 'V-207234'
  tag rid: 'SV-207234r856706_rule'
  tag stig_id: 'SRG-NET-000334-VPN-001260'
  tag gtitle: 'SRG-NET-000334'
  tag fix_id: 'F-7494r378324_fix'
  tag 'documentable'
  tag legacy: ['SV-106285', 'V-97147']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
