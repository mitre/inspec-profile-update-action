control 'SV-16955' do
  title 'Terminal Services is not configured to delete temporary folders.'
  desc 'This setting, which is located under the Temporary Folders section of the Terminal Services configuration option, controls the deletion of the temporary folders when the session is terminated.  Temporary folders should always be deleted after a session is over to prevent hard disk clutter and potential leakage of information.'
  desc 'fix', '2008/Vista - Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Temporary Folders “Do Not Delete Temp Folder upon Exit” will be set to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-3456'
  tag rid: 'SV-16955r1_rule'
  tag gtitle: 'TS/RDS - Delete Temp Folders'
  tag fix_id: 'F-16026r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
