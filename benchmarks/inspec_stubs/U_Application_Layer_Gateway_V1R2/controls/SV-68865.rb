control 'SV-68865' do
  title 'The ALG must recognize only system-generated session identifiers.'
  desc "Network elements (depending on function) utilize sessions and session identifiers to control application behavior and user access. If an attacker can guess the session identifier, or can inject or manually insert session information, the valid user's application session can be compromised.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement focuses on communications protection for the application session rather than for the network packet."
  desc 'check', 'Verify the ALG recognizes only system-generated session identifiers.

If the ALG does not recognize only system-generated session identifiers, this is a finding.'
  desc 'fix', 'Configure ALG to recognize only system-generated session identifiers.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54619'
  tag rid: 'SV-68865r1_rule'
  tag stig_id: 'SRG-NET-000233-ALG-000115'
  tag gtitle: 'SRG-NET-000233-ALG-000115'
  tag fix_id: 'F-59475r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
