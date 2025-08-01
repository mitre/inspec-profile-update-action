control 'SV-76961' do
  title 'ColdFusion must enable UUID for session identifier generation.'
  desc 'Unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of session identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

ColdFusion offers session ID randomness and uniqueness by enabling UUID for the session ID.  Without this option enabled, session values are sequential and become easy to hijack through guessing.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu. 

If "Use UUID for cftoken" is not checked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Check "Use UUID for cftoken" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62471'
  tag rid: 'SV-76961r1_rule'
  tag stig_id: 'CF11-05-000167'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag fix_id: 'F-68391r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
