control 'SV-68861' do
  title 'The ALG must protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).'
  desc 'check', 'Verify the ALG protects the authenticity of communications sessions. 

If the ALG does not protect the authenticity of communications sessions, this is a finding.'
  desc 'fix', 'Configure ALG to protect the authenticity of communications sessions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54615'
  tag rid: 'SV-68861r1_rule'
  tag stig_id: 'SRG-NET-000230-ALG-000113'
  tag gtitle: 'SRG-NET-000230-ALG-000113'
  tag fix_id: 'F-59471r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
