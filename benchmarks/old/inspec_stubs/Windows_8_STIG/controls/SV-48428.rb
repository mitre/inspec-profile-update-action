control 'SV-48428' do
  title 'The VPN client on mobile devices must use either IPSec or SSL/TLS when connecting to DoD networks.'
  desc 'Use of non-standard communications protocols can affect both the availability and confidentiality of communications.  IPSec and SSL/TLS are both well-known and tested protocols that provide strong assurance with respect to both IA and interoperability.'
  desc 'check', 'Verify the VPN client on mobile devices is configured to use IPSec or SSL/TLS for connections to DoD networks.  If it does not, this is a finding.

Procedures will vary depending on the VPN client used.'
  desc 'fix', 'Configure the VPN client on mobile devices to use IPSec or SSL/TLS when connecting to DoD networks.

Procedures will vary depending on the VPN client used.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36754'
  tag rid: 'SV-48428r2_rule'
  tag stig_id: 'WN08-MO-000003'
  tag gtitle: 'WN08-MO-000003'
  tag fix_id: 'F-41559r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWN-1'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
