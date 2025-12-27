control 'SV-29399' do
  title 'The system is configured to allow the display of the last user name on the logon screen.'
  desc 'The user name of the last user to log onto a system will not be displayed.  This eliminates half of the Userid/Password equation that an unauthorized person would need to log on.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive logon: Do not display last user name” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-11806'
  tag rid: 'SV-29399r1_rule'
  tag gtitle: 'Display of Last User Name'
  tag fix_id: 'F-11088r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
