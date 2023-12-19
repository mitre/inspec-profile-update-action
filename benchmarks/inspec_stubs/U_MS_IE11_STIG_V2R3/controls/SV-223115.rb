control 'SV-223115' do
  title 'Internet Explorer Processes for Restrict File Download must be enforced (iexplore).'
  desc %q(In certain circumstances, websites can initiate file download prompts without interaction from users. This technique can allow websites to put unauthorized files on users' hard drives if they click the wrong button and accept the download. If you configure the Restrict File Download\Internet Explorer Processes policy setting to "Enabled", file download prompts that are not user-initiated are blocked for Internet Explorer processes. If you configure this policy setting as "Disabled", prompting will occur for file downloads that are not user-initiated for Internet Explorer processes. Note: This setting is configured as "Enabled" in all environments specified in this guide to help prevent attackers from placing arbitrary code on users' computers.)
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict File Download -> 'Internet Explorer Processes' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD Criteria: If the value "iexplore.exe" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict File Download -> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24788r428895_chk'
  tag severity: 'medium'
  tag gid: 'V-223115'
  tag rid: 'SV-223115r428897_rule'
  tag stig_id: 'DTBI640-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24776r428896_fix'
  tag 'documentable'
  tag legacy: ['SV-59647', 'V-46781']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
