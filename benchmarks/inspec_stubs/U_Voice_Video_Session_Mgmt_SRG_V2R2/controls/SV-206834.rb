control 'SV-206834' do
  title 'The Voice Video Session Manager must protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. VC and UC require the use of TLS mutual authentication (two-way/bidirectional) for authenticity.'
  desc 'check', 'Verify the Voice Video Session Manager protects the authenticity of communications sessions.

If the Voice Video Session Manager does not protect the authenticity of communications sessions, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to protect the authenticity of communications sessions.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7089r364691_chk'
  tag severity: 'high'
  tag gid: 'V-206834'
  tag rid: 'SV-206834r508661_rule'
  tag stig_id: 'SRG-NET-000230-VVSM-00023'
  tag gtitle: 'SRG-NET-000230'
  tag fix_id: 'F-7089r364692_fix'
  tag 'documentable'
  tag legacy: ['SV-76593', 'V-62103']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
