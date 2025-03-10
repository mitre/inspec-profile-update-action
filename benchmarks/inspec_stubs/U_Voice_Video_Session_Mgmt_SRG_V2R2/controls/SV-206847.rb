control 'SV-206847' do
  title 'The Voice Video Session Manager must authenticate each Voice Video peer (trunk) before registration.'
  desc 'Device registration is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices and trunks can access the system. Registration is the process of authorizing endpoints and trunks to communicate with the session manager. Registration occurs with the SIP server in VoIP systems and with a gatekeeper in H.323 systems. Without enforcing registration, an adversary could impersonate a legitimate device or peer on the Voice Video network.'
  desc 'check', 'Verify the Voice Video Session Manager authenticates all Voice Video peers (trunks) before establishing any connection.

If the Voice Video Session Manager does not authenticate all Voice Video peers (trunks) before establishing any connection, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to authenticate all Voice Video peers (trunks) before registration.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7102r364730_chk'
  tag severity: 'medium'
  tag gid: 'V-206847'
  tag rid: 'SV-206847r508661_rule'
  tag stig_id: 'SRG-NET-000343-VVSM-00055'
  tag gtitle: 'SRG-NET-000343'
  tag fix_id: 'F-7102r364731_fix'
  tag 'documentable'
  tag legacy: ['SV-86309', 'V-71685']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
