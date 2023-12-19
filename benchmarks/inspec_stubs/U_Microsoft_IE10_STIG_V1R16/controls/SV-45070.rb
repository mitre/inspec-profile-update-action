control 'SV-45070' do
  title 'Active content from CDs must be disallowed to run on user machines.'
  desc 'This policy setting allows you to manage whether users receive a dialog requesting permission for active content on a CD to run. If you enable this policy setting, active content on a CD will run without a prompt. If you disable this policy setting, active content on a CD will always prompt before running. If you do not configure this policy, users can choose whether to be prompted before running active content on a CD.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> "Allow active content from CDs to run on user machines" must be "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_LOCALMACHINE_LOCKDOWN\\Settings 

Criteria: If the value LOCALMACHINE_CD_UNLOCK is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> "Allow active content from CDs to run on user machines" to "Disabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42442r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15497'
  tag rid: 'SV-45070r1_rule'
  tag stig_id: 'DTBI340'
  tag gtitle: "DTBI340 - Active content from CD's"
  tag fix_id: 'F-38477r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
