control 'SV-16658' do
  title 'Users must be notified if the logon server was inaccessible and cached credentials were used.'
  desc 'Notifying a user whether cached credentials were used may make them aware of connection issues.'
  desc 'fix', 'If the system is not a member of a domain, this is NA.
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Logon Options -> "Report when logon server was not available during user logon" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15719'
  tag rid: 'SV-16658r3_rule'
  tag gtitle: 'Logon – Report Logon Server'
  tag fix_id: 'F-63555r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
