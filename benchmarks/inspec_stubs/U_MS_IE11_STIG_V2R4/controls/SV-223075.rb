control 'SV-223075' do
  title 'Security checking features must be enforced.'
  desc 'This policy setting turns off the Security Settings Check feature, which checks Internet Explorer security settings to determine when the settings put Internet Explorer at risk. If you enable this policy setting, the security settings check will not be performed. If you disable or do not configure this policy setting, the security settings check will be performed.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> 'Turn off the Security Settings Check feature' must be 'Disabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Security Criteria: If the value "DisableSecuritySettingsCheck" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> 'Turn off the Security Settings Check feature' to 'Disabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24748r428775_chk'
  tag severity: 'medium'
  tag gid: 'V-223075'
  tag rid: 'SV-223075r879887_rule'
  tag stig_id: 'DTBI325-IE11'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24736r428776_fix'
  tag 'documentable'
  tag legacy: ['SV-59485', 'V-46621']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
