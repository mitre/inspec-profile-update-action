control 'SV-223133' do
  title 'Internet Explorer Processes for Notification Bars must be enforced (Explorer).'
  desc 'This policy setting allows you to manage whether the Notification Bar is displayed for Internet Explorer processes when file or code installs are restricted. By default, the Notification Bar is displayed for Internet Explorer processes. If you enable this policy setting, the Notification Bar will be displayed for Internet Explorer processes. If you disable this policy setting, the Notification Bar will not be displayed for Internet Explorer processes. If you do not configure this policy setting, the Notification Bar will be displayed for Internet Explorer processes.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar-> 'Internet Explorer Processes' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND Criteria: If the value "explorer.exe" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar-> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24806r428949_chk'
  tag severity: 'medium'
  tag gid: 'V-223133'
  tag rid: 'SV-223133r428951_rule'
  tag stig_id: 'DTBI825-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24794r428950_fix'
  tag 'documentable'
  tag legacy: ['SV-59727', 'V-46861']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
