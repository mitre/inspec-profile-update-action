control 'SV-59589' do
  title 'Internet Explorer Processes for MK protocol must be enforced (iexplore).'
  desc 'The MK Protocol Security Restriction policy setting reduces attack surface area by blocking the seldom used MK protocol. Some older web applications use the MK protocol to retrieve information from compressed files. Because the MK protocol is not widely used, it should be blocked wherever it is not needed. Setting this policy to "Enabled"; blocks the MK protocol for Windows Explorer and Internet Explorer, which causes resources that use the MK protocol to fail. Disabling this setting allows applications to use the MK protocol API. This guide recommends you configure this setting to "Enabled" to block the MK protocol unless specifically needed in the environment. Note: Because resources that use the MK protocol will fail when deploying this setting, ensure none of the applications use the MK protocol.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction -> 'Internet Explorer Processes' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL Criteria: If the value "iexplore.exe" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction -> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49867r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46725'
  tag rid: 'SV-59589r1_rule'
  tag stig_id: 'DTBI605-IE11'
  tag gtitle: 'DTBI605-IE11-MK protocol - iexplore'
  tag fix_id: 'F-50481r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
