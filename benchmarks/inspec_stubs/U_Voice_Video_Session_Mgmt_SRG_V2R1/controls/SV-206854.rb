control 'SV-206854' do
  title 'The Voice Video Session Manager must prohibit remote activation of collaborative computing devices (excluding centrally managed, dedicated videoconference suites located in approved videoconference locations).'
  desc 'An adversary may be able to gain access to information on whiteboards, listen to conversations on a microphone, or view areas with a camera since collaboration equipment is typically not designed with security access controls and protection measures of more sophisticated networked clients. Collaborative computing devices include, for example, networked whiteboards, cameras, and microphones.

This requirement applies to collaboration applications that control collaborative computing devices. Exceptions to this would require acceptance of the risk by a cognizant AO. This requirement is not intended to prohibit remote activation of centrally managed, dedicated videoconferencing Suites for the purpose of remote testing of the equipment.'
  desc 'check', 'Verify the Voice Video Session Manager prohibits remote activation of collaborative computing devices. For centrally managed, dedicated videoconference suites located in approved videoconference locations with full documentation, this requirement is not applicable.

If the Voice Video Session Manager does not prohibit remote activation of collaborative computing devices, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager, except for centrally managed, dedicated videoconference suites located in approved videoconference locations, to prohibit remote activation of collaborative computing devices.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7109r364751_chk'
  tag severity: 'medium'
  tag gid: 'V-206854'
  tag rid: 'SV-206854r508661_rule'
  tag stig_id: 'SRG-NET-000512-VVSM-00012'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7109r364752_fix'
  tag 'documentable'
  tag legacy: ['V-62139', 'SV-76629']
  tag cci: ['CCI-001150']
  tag nist: ['SC-15 a']
end
