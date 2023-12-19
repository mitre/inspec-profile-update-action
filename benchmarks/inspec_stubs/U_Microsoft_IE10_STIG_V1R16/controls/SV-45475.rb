control 'SV-45475' do
  title 'Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer).'
  desc "Users often choose to install software such as ActiveX controls that are not permitted by their organization's security policy. Such software can pose significant security and privacy risks to networks. This policy setting enables blocking of ActiveX control installation prompts for Internet Explorer processes. If you enable this policy setting, prompts for ActiveX control installations will be blocked for Internet Explorer processes. If you disable this policy setting, prompts for ActiveX control installations will not be blocked and these prompts will be displayed to users. If you do not configure this policy setting, the user's preference will be used to determine whether to block ActiveX control installations for Internet Explorer processes."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install -> "Internet Explorer Processes" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL

Criteria: If the value explorer.exe is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install -> "Internet Explorer Processes" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42824r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22687'
  tag rid: 'SV-45475r1_rule'
  tag stig_id: 'DTBI1010'
  tag gtitle: 'DTBI1010 - Restrict ActiveX Install - Explorer'
  tag fix_id: 'F-38872r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
