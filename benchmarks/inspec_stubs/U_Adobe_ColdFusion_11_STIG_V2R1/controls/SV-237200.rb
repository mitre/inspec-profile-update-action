control 'SV-237200' do
  title 'ColdFusion must use J2EE session variables.'
  desc 'Unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of session identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

By enabling J2EE session management, each session is given a unique and non-sequential session id which is shared between the JVM and the ColdFusion application allowing for easier session management.  J2EE session management stores the session data within a cookie stored in memory which will only exist while the session is valid.  When J2EE sessions management is not used, the cookie is stored on the hard drive allowing for a cookie that can be easily harvested by an attacker.'
  desc 'check', 'Within the Administrator Console, navigate to the "Memory Variables" page under the "Server Settings" menu.

If "Use J2EE session variables" is not checked, this is a finding.'
  desc 'fix', 'Navigate to the "Memory Variables" page under the "Server Settings" menu.  Check "Use J2EE session variables" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40419r641693_chk'
  tag severity: 'medium'
  tag gid: 'V-237200'
  tag rid: 'SV-237200r641695_rule'
  tag stig_id: 'CF11-05-000168'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag fix_id: 'F-40382r641694_fix'
  tag 'documentable'
  tag legacy: ['SV-76963', 'V-62473']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
