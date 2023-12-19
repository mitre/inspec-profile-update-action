control 'SV-29590' do
  title 'The system allows shutdown from the logon dialog box.'
  desc 'Preventing display of the shutdown button in the logon dialog box may encourage a hard shut down with the power button.  (However, displaying the shutdown button may allow individuals to shut down a system anonymously.)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Shutdown: Allow system to be shutdown without having to log on” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-1075'
  tag rid: 'SV-29590r1_rule'
  tag gtitle: 'Display Shutdown Button'
  tag fix_id: 'F-17274r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
