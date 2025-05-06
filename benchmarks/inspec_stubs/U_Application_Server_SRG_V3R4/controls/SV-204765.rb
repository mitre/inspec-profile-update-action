control 'SV-204765' do
  title 'The application server must recognize only system-generated session identifiers.'
  desc 'This requirement focuses on communications protection at the application session, versus network packet level. The intent of this control is to establish grounds for confidence at each end of a communications session in the ongoing identity of the other party and in the validity of the information being transmitted.

Unique session IDs are the opposite of sequentially generated session IDs which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of said identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.'
  desc 'check', 'Review the application server configuration to determine if the application server recognizes only system-generated session identifiers.

If the application server does not recognize only system-generated session identifiers, this is a finding.'
  desc 'fix', 'Design the application server to recognize only system-generated session identifiers.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4885r282942_chk'
  tag severity: 'medium'
  tag gid: 'V-204765'
  tag rid: 'SV-204765r879638_rule'
  tag stig_id: 'SRG-APP-000223-AS-000151'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-4885r282943_fix'
  tag 'documentable'
  tag legacy: ['V-35421', 'SV-46708']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
