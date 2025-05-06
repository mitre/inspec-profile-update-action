control 'SV-223073' do
  title 'Internet Explorer must be configured to disallow users to change policies.'
  desc 'Users who change their Internet Explorer security settings could enable the execution of dangerous types of code from the Internet and websites listed in the Restricted Sites zone in the browser. This setting prevents users from changing the Internet Explorer policies on the machine. Policy changes should be made by administrators only, so this setting should be enabled. If you enable this policy setting, you disable the "Custom level" button and "Security" level for this zone slider on the Security tab in the Internet Options dialog box. If this policy setting is disabled or not configured, users will be able to change the settings for security zones. It prevents users from changing security zone policy settings that are established by the administrator.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer 'Security Zones: Do not allow users to change policies' must be 'Enabled'.  Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Criteria: If the value "Security_options_edit" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer 'Security Zones: Do not allow users to change policies' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24746r428769_chk'
  tag severity: 'medium'
  tag gid: 'V-223073'
  tag rid: 'SV-223073r879887_rule'
  tag stig_id: 'DTBI319-IE11'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24734r428770_fix'
  tag 'documentable'
  tag legacy: ['SV-59481', 'V-46617']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
