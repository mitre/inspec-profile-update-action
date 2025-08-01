control 'SV-206804' do
  title 'The Voice Video Endpoint must prevent installation of untrusted third-party software.'
  desc 'Unauthorized third-party software is challenging the security posture of DoD. Most established vendors have developed a patch management process that prevents risk, resulting in an estimated 80 percent of threats arising from third-party software. Preventing users from installing third-party software limits organizational exposure. Additionally, preventing installation of untrusted software further reduces risk to the network. Vendors that prevent installation of all third-party software meet the intent of this requirement.'
  desc 'check', 'Verify the Voice Video Endpoint prevents installation of untrusted third-party software.

If the Voice Video Endpoint does not prevent installation of untrusted third-party software, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to prevent installation of untrusted third-party software.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7060r363935_chk'
  tag severity: 'medium'
  tag gid: 'V-206804'
  tag rid: 'SV-206804r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00058'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7060r363936_fix'
  tag 'documentable'
  tag legacy: ['V-66797', 'SV-81287']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
