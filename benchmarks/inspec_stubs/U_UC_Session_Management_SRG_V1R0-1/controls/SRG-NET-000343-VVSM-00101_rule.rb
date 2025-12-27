control 'SRG-NET-000343-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to authenticate each Voice Video Endpoint device before registration.'
  desc 'Device registration is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific preauthorized devices and trunks can access the system. Registration is the process of authorizing endpoints and trunks to communicate with the session manager. Registration occurs with the SIP server in VoIP systems and with a gatekeeper in H.323 systems. Without enforcing registration, an adversary could impersonate a legitimate device or peer on the Voice Video network.'
  desc 'check', 'Verify the Unified Communications Session Manager authenticates all Voice Video Endpoint devices before establishing any connection.

If the Unified Communications Session Manager does not authenticate all Voice Video Endpoint devices before establishing any connection, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to authenticate all Voice Video Endpoint devices before registering those devices.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000343-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000343-VVSM-00101'
  tag rid: 'SRG-NET-000343-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000343-VVSM-00101'
  tag gtitle: 'SRG-NET-000343-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000343-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
