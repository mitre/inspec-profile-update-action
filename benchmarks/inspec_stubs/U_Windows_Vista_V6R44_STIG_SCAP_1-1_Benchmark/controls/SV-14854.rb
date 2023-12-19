control 'SV-14854' do
  title 'Require username and password to elevate a running application.'
  desc 'This check verifies that the system is configured to always require users to type in a user name and password to elevate a running application.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface “Enumerate administrator accounts on elevation” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14243'
  tag rid: 'SV-14854r1_rule'
  tag gtitle: 'Enumerate Administrator Accounts on Elevation'
  tag fix_id: 'F-13569r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
