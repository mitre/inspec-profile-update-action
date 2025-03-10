control 'SV-59647' do
  title 'Internet Explorer Processes for Restrict File Download must be enforced (iexplore).'
  desc %q(In certain circumstances, websites can initiate file download prompts without interaction from users. This technique can allow websites to put unauthorized files on users' hard drives if they click the wrong button and accept the download. If you configure the Restrict File Download\Internet Explorer Processes policy setting to "Enabled", file download prompts that are not user-initiated are blocked for Internet Explorer processes. If you configure this policy setting as "Disabled", prompting will occur for file downloads that are not user-initiated for Internet Explorer processes. Note: This setting is configured as "Enabled" in all environments specified in this guide to help prevent attackers from placing arbitrary code on users' computers.)
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict File Download -> 'Internet Explorer Processes' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD Criteria: If the value "iexplore.exe" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict File Download -> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49879r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46781'
  tag rid: 'SV-59647r1_rule'
  tag stig_id: 'DTBI640-IE11'
  tag gtitle: 'DTBI640-IE11-Restrict File download - iexplore'
  tag fix_id: 'F-50531r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
