control 'SV-29017' do
  title 'The Recovery Console SET command is enabled.'
  desc 'Enabling this option enables the Recovery Console SET command, which allows you to set Recovery Console environment variables.  This permits floppy copy and access to all drives and folders.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Recovery Console: Allow floppy copy and access to all drives and folders” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1158'
  tag rid: 'SV-29017r1_rule'
  tag gtitle: 'Recovery Console - SET Command'
  tag fix_id: 'F-28812r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECCD-1'
end
