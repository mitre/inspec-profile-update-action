control 'SV-59479' do
  title 'Internet Explorer must be set to disallow users to add/delete sites.'
  desc 'This setting prevents users from adding sites to various security zones. Users should not be able to add sites to different zones, as this could allow them to bypass security controls of the system. If you do not configure this policy setting, users will be able to add or remove sites from the Trusted Sites and Restricted Sites zones at will and change settings in the Local Intranet zone. This configuration could allow sites that host malicious mobile code to be added to these zones, and users could execute the code.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer 'Security Zones: Do not allow users to add/delete sites' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Criteria: If the value "Security_zones_map_edit" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer 'Security Zones: Do not allow users to add/delete sites' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49781r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46615'
  tag rid: 'SV-59479r1_rule'
  tag stig_id: 'DTBI318-IE11'
  tag gtitle: 'DTBI318-IE11-Addition and deletion of sites'
  tag fix_id: 'F-50385r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
