control 'SV-206846' do
  title 'The Voice Video Session Manager must authenticate each Voice Video endpoint devices before registration.'
  desc 'Device registration is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system. Registration is the process of authorizing endpoints to communicate with the session manager. Registration occurs with the SIP server in VoIP systems and with a gatekeeper in H.323 systems. Without enforcing registration, an adversary could impersonate a legitimate device on the Voice Video network.'
  desc 'check', 'Verify the Voice Video Session Manager authenticates all Voice Video endpoint devices before establishing any connection.

If the Voice Video Session Manager does not authenticate all Voice Video endpoint devices before establishing any connection, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to authenticate all Voice Video endpoint devices before registering those devices.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7101r364727_chk'
  tag severity: 'medium'
  tag gid: 'V-206846'
  tag rid: 'SV-206846r508661_rule'
  tag stig_id: 'SRG-NET-000343-VVSM-00005'
  tag gtitle: 'SRG-NET-000343'
  tag fix_id: 'F-7101r364728_fix'
  tag 'documentable'
  tag legacy: ['V-62125', 'SV-76615']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
