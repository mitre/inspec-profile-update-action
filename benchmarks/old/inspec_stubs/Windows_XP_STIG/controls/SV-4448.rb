control 'SV-4448' do
  title 'Group Policy objects are not reprocessed if they have not changed.'
  desc 'Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy “Registry Policy Processing” to “Enabled” and select the option “Process even if the Group Policy objects have not changed”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-4448'
  tag rid: 'SV-4448r1_rule'
  tag gtitle: 'Group Policy - Registry Policy Processing'
  tag fix_id: 'F-28955r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
