control 'SV-223142' do
  title 'Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved).'
  desc "Users often choose to install software such as ActiveX controls that are not permitted by their organization's security policy. Such software can pose significant security and privacy risks to networks. This policy setting enables blocking of ActiveX control installation prompts for Internet Explorer processes. If you enable this policy setting, prompts for ActiveX control installations will be blocked for Internet Explorer processes. If you disable this policy setting, prompts for ActiveX control installations will not be blocked and these prompts will be displayed to users. If you do not configure this policy setting, the user's preference will be used to determine whether to block ActiveX control installations for Internet Explorer processes."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install -> 'Internet Explorer Processes' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL   Criteria: If the value "(Reserved)" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install -> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24815r428976_chk'
  tag severity: 'medium'
  tag gid: 'V-223142'
  tag rid: 'SV-223142r879573_rule'
  tag stig_id: 'DTBI900-IE11'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-24803r428977_fix'
  tag 'documentable'
  tag legacy: ['SV-59763', 'V-46897']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
