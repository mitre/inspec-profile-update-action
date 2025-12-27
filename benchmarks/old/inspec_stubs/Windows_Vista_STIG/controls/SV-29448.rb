control 'SV-29448' do
  title 'The classic logon screen must be required for user logons.'
  desc 'The classic logon screen requires users to enter a logon name and password to access a system.  The simple logon screen or Welcome screen displays usernames for selection, providing part of the necessary logon information.'
  desc 'fix', 'If the system is a member of a domain, this is NA.
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Always use classic logon" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15680'
  tag rid: 'SV-29448r2_rule'
  tag gtitle: 'Classic Logon'
  tag fix_id: 'F-63535r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
