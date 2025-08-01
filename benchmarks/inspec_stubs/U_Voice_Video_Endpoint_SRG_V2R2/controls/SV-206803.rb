control 'SV-206803' do
  title 'The Voice Video Endpoint must prevent the user from installing third-party software.'
  desc 'Unauthorized third-party software is challenging the security posture of DoD. Most established vendors have developed patch management process that prevents risk, resulting in an estimated 80 percent of threats arise from third-party software. Preventing users from installing third-party software limits organizational exposure. Additionally, preventing installation of untrusted software further reduces risk to the network.'
  desc 'check', 'Verify the Voice Video Endpoint prevents the user from installing third-party software.

If the Voice Video Endpoint does not prevent the user from installing third-party software, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to prevent the user from installing third-party software.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7059r363932_chk'
  tag severity: 'medium'
  tag gid: 'V-206803'
  tag rid: 'SV-206803r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00057'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7059r363933_fix'
  tag 'documentable'
  tag legacy: ['V-66795', 'SV-81285']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
