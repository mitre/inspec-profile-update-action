control 'SV-29535' do
  title 'The system must be configured to require case insensitivity for non-Windows subsystems.'
  desc 'This setting controls the behavior of non-Windows subsystems when dealing with the case of arguments or commands.  Case sensitivity could lead to the access of files or commands that must be restricted.  To prevent this from happening, case insensitivity restrictions must be required.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System Objects: Require case insensitivity for non-Windows subsystems" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-3385'
  tag rid: 'SV-29535r2_rule'
  tag gtitle: 'Case Insensitivity for Non-Windows'
  tag fix_id: 'F-65633r2_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
