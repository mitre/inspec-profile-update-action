control 'SV-223072' do
  title 'Internet Explorer must be set to disallow users to add/delete sites.'
  desc 'This setting prevents users from adding sites to various security zones. Users should not be able to add sites to different zones, as this could allow them to bypass security controls of the system. If you do not configure this policy setting, users will be able to add or remove sites from the Trusted Sites and Restricted Sites zones at will and change settings in the Local Intranet zone. This configuration could allow sites that host malicious mobile code to be added to these zones, and users could execute the code.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer 'Security Zones: Do not allow users to add/delete sites' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Criteria: If the value "Security_zones_map_edit" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer 'Security Zones: Do not allow users to add/delete sites' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24745r428766_chk'
  tag severity: 'medium'
  tag gid: 'V-223072'
  tag rid: 'SV-223072r879587_rule'
  tag stig_id: 'DTBI318-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24733r428767_fix'
  tag 'documentable'
  tag legacy: ['SV-59479', 'V-46615']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
